"""Syntax-aware, dependency-free SAST analysis.

This module intentionally does not execute regular expressions.  Python is
analysed from its AST; JavaScript/TypeScript and configuration files use a
token stream that preserves identifiers, strings, call sites and locations.
The engine is deliberately separated from the YAML catalogue: YAML supplies
the rule metadata while this module supplies semantic predicates.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class SemanticMatch:
    rule_id: str
    line_number: int
    column_number: int
    matched_text: str
    analyzer: str
    confidence_delta: float = 0.0


@dataclass(frozen=True)
class Token:
    value: str
    kind: str
    line: int
    column: int


def analyze(content: str, file_path: str) -> list[SemanticMatch]:
    suffix = Path(file_path).suffix.lower()
    findings: list[SemanticMatch] = []
    if suffix == ".py":
        analyzer = _PythonAnalyzer(content)
        findings.extend(analyzer.run())
        if not analyzer.parsed:
            findings.extend(_PythonTokenAnalyzer(content).run())
            findings.extend(_ConfigurationAnalyzer(content, suffix).run())
    elif suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        findings.extend(_JavaScriptAnalyzer(content).run())
    elif suffix in {".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".tf", ".pem", ".key", ".crt"}:
        findings.extend(_ConfigurationAnalyzer(content, suffix).run())
    return _dedupe(findings)


class _PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, content: str):
        self.content = content
        self.lines = content.splitlines()
        self.matches: list[SemanticMatch] = []
        self.aliases: dict[str, str] = {}
        self.tainted: set[str] = set()
        self.security_names: set[str] = set()
        self.parsed = False

    def run(self) -> list[SemanticMatch]:
        try:
            tree = ast.parse(self.content)
            self.parsed = True
            self.visit(tree)
        except SyntaxError:
            # A malformed Python source file is still inspected by the safe
            # lexical configuration pass; do not silently interpret it as a
            # valid program.
            return []
        return self.matches

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.aliases[item.asname or item.name.split(".")[0]] = item.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for item in node.names:
            self.aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [name for target in node.targets for name in _assigned_names(target)]
        value_tainted = _python_is_tainted(node.value, self.tainted)
        for name in names:
            if value_tainted:
                self.tainted.add(name)
            if _looks_security_name(name):
                self.security_names.add(name)
        self._assignment_rules(node, names)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        names = list(_assigned_names(node.target))
        if node.value and _python_is_tainted(node.value, self.tainted):
            self.tainted.update(names)
        if node.value:
            self._assignment_rules(node, names)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _python_call_name(node.func, self.aliases)
        line, column = node.lineno, node.col_offset + 1
        text = _source_line(self.lines, line)
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        first = node.args[0] if node.args else None

        if name in {"eval", "builtins.eval"}:
            self._add("SAST_PY_EVAL", line, column, text, "python-ast")
        if name in {"exec", "builtins.exec"}:
            self._add("SAST_PY_EXEC", line, column, text, "python-ast")
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            self._add("SAST_PY_PICKLE_LOADS", line, column, text, "python-ast")
        if name == "yaml.load":
            self._add("SAST_PY_YAML_LOAD", line, column, text, "python-ast")
        if name in {"subprocess.run", "subprocess.call", "subprocess.popen", "subprocess.check_output"} and _literal_bool(keywords.get("shell")) is True:
            self._add("SAST_PY_SUBPROCESS_SHELL", line, column, text, "python-ast")
        if name.startswith("requests.") and _literal_bool(keywords.get("verify")) is False:
            self._add("SAST_PY_REQUESTS_VERIFY_FALSE", line, column, text, "python-ast")
        if name.startswith("httpx.") and _literal_bool(keywords.get("verify")) is False:
            self._add("SAST_PY_HTTPX_VERIFY_FALSE", line, column, text, "python-ast")
        if name in {"ssl._create_unverified_context", "ssl.create_default_context"} and (name.endswith("_unverified_context") or _literal_bool(keywords.get("check_hostname")) is False):
            self._add("SAST_PY_SSL_UNVERIFIED_CONTEXT", line, column, text, "python-ast")
        if name in {"jinja2.Template", "Template"}:
            self._add("SAST_PY_JINJA_TEMPLATE_UNSAFE", line, column, text, "python-ast")
        if name in {"jinja2.Environment", "Environment"} and _literal_bool(keywords.get("autoescape")) is False:
            self._add("SAST_PY_JINJA_AUTOESCAPE_DISABLED", line, column, text, "python-ast")
        if name in {"hashlib.md5", "hashlib.new"} and (name == "hashlib.md5" or _literal_string(first).lower() == "md5"):
            self._add("WEAK_HASH_MD5_PY_HASHLIB", line, column, text, "python-ast")
        if name in {"hashlib.sha1", "hashlib.new"} and (name == "hashlib.sha1" or _literal_string(first).lower() in {"sha1", "sha-1"}):
            self._add("WEAK_HASH_SHA1_PY_HASHLIB", line, column, text, "python-ast")
        if name.lower().endswith(".aes.new") or name.lower() == "aes.new":
            if any(_attribute_name(arg).endswith("MODE_ECB") for arg in node.args):
                self._add("WEAK_CIPHER_AES-ECB", line, column, text, "python-ast")
        if name.lower().endswith((".des.new", ".des3.new", ".arc4.new", ".rc4.new")) or name.lower() in {"des.new", "des3.new", "arc4.new", "rc4.new"}:
            self._add("WEAK_CIPHER_DES", line, column, text, "python-ast")
        if name.lower().endswith("rsa.generate") or name.lower() == "rsa.generate":
            size = _literal_int(keywords.get("bits") or first)
            if size is not None and size < 2048:
                self._add("SMALL_RSA_KEY", line, column, text, "python-ast")
        if name.endswith("set_cookie") and _looks_auth_cookie(node):
            if not all(key in keywords for key in ("secure", "httponly", "samesite")):
                self._add("SAST_FASTAPI_INSECURE_COOKIE_FLAGS", line, column, text, "python-ast")
        if name in {"jwt.decode", "jose.jwt.decode"} and _jwt_verification_disabled(node, keywords):
            self._add("SAST_JWT_VERIFY_DISABLED", line, column, text, "python-ast")
        if name.endswith("add_middleware") and _cors_is_permissive(node):
            self._add("SAST_FASTAPI_CORS_WILDCARD_CREDENTIALS", line, column, text, "python-ast")
        if _is_sql_sink(name) and first is not None and _python_sql_dynamic(first, self.tainted):
            self._add("SAST_SQL_CONCAT", line, column, text, "python-taint")
        if _is_path_sink(name) and first is not None and _python_is_tainted(first, self.tainted):
            self._add("SAST_PATH_TRAVERSAL", line, column, text, "python-taint")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if _python_call_name(node, self.aliases) == "ssl.CERT_NONE":
            self._add("SAST_PY_SSL_UNVERIFIED_CONTEXT", node.lineno, node.col_offset + 1, _source_line(self.lines, node.lineno), "python-ast")
        self.generic_visit(node)

    def _assignment_rules(self, node: ast.AST, names: list[str]) -> None:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0) + 1
        text = _source_line(self.lines, line)
        value = getattr(node, "value", None)
        if not value:
            return
        if any(_looks_security_name(name) for name in names) and _python_call_name(value, self.aliases) in {"random.random", "random.randint", "random.choice", "random.choices"}:
            self._add("SAST_PY_RANDOM_TOKEN", line, column, text, "python-dataflow")
        if any(name.lower() in {"iv", "nonce"} or name.lower().endswith(("_iv", "_nonce")) for name in names) and _literal_string(value):
            self._add("SAST_PY_STATIC_IV_NONCE", line, column, text, "python-ast")
        if any(name.lower() in {"debug", "flask_debug"} for name in names) and _literal_bool(value) is True:
            self._add("SAST_PY_DEBUG_MODE", line, column, text, "python-ast")
        if isinstance(value, ast.Constant) and isinstance(value.value, str) and any(_looks_secret_name(name) for name in names):
            self._add(_secret_rule_for(names, value.value), line, column, text, "token-literal")

    def _add(self, rule_id: str, line: int, column: int, text: str, analyzer: str, confidence_delta: float = 0.0) -> None:
        self.matches.append(SemanticMatch(rule_id, line, column, text, analyzer, confidence_delta))


class _JavaScriptAnalyzer:
    def __init__(self, content: str):
        self.content = content
        self.tokens = _lex_javascript(content)
        self.matches: list[SemanticMatch] = []
        self.tainted: set[str] = set()

    def run(self) -> list[SemanticMatch]:
        for index, token in enumerate(self.tokens):
            if token.kind != "identifier":
                continue
            path = _token_path(self.tokens, index)
            next_value = _next_value(self.tokens, index + _path_token_width(self.tokens, index))
            line_tokens = _line_tokens(self.tokens, token.line)
            line_text = " ".join(item.value for item in line_tokens)
            previous = _previous_value(self.tokens, index)
            assignment_name = _assigned_name_before(self.tokens, index)
            if path == "eval" and next_value == "(":
                self._add("SAST_JS_EVAL", token, line_text, "javascript-token")
            if path in {"child_process.exec", "child_process.execSync", "exec", "execSync"} and next_value == "(":
                self._add("SAST_NODE_EXEC", token, line_text, "javascript-token")
            if path in {"CryptoJS.MD5", "md5"} and next_value == "(":
                self._add("WEAK_HASH_CRYPTOJS_MD5", token, line_text, "javascript-token")
            if path in {"CryptoJS.SHA1", "sha1"} and next_value == "(":
                self._add("WEAK_HASH_CRYPTOJS_SHA1", token, line_text, "javascript-token")
            if path == "Math.random" and next_value == "(" and assignment_name and (_looks_security_name(assignment_name) or "token" in self.content.lower()):
                self._add("SAST_JS_MATH_RANDOM_TOKEN", token, line_text, "javascript-dataflow")
            if path.endswith("innerHTML") and next_value == "=":
                self._add("SAST_JS_INNERHTML", token, line_text, "javascript-token")
            if path.endswith("NODE_TLS_REJECT_UNAUTHORIZED") and next_value == "=" and _next_string_or_number(self.tokens, index) in {"0", "false"}:
                self._add("SAST_NODE_TLS_REJECT_UNAUTHORIZED_FALSE", token, line_text, "javascript-token")
            if path in {"fs.readFile", "fs.readFileSync", "fs.createReadStream", "sendFile"} and next_value == "(" and _call_has_request_source(self.tokens, index):
                self._add("SAST_PATH_TRAVERSAL", token, line_text, "javascript-taint")
            if path in {"query", "execute", "executeQuery"} and next_value == "(" and _call_has_dynamic_sql(self.tokens, index):
                self._add("SAST_SQL_CONCAT", token, line_text, "javascript-taint")
            if previous in {"const", "let", "var"} and next_value == "=" and _looks_secret_name(token.value):
                literal = _next_string_or_number(self.tokens, index)
                if literal:
                    self._add(_secret_rule_for([token.value], literal), token, line_text, "token-literal")
        return self.matches

    def _add(self, rule_id: str, token: Token, text: str, analyzer: str) -> None:
        self.matches.append(SemanticMatch(rule_id, token.line, token.column, text, analyzer))


class _ConfigurationAnalyzer:
    def __init__(self, content: str, suffix: str):
        self.lines = content.splitlines()
        self.suffix = suffix
        self.matches: list[SemanticMatch] = []

    def run(self) -> list[SemanticMatch]:
        for number, line in enumerate(self.lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            if "-----BEGIN " in stripped and "PRIVATE KEY-----" in stripped:
                self._add("SAST_PRIVATE_KEY_BLOCK", number, line.find("-----BEGIN") + 1, line, "configuration-token")
            key, value, column = _configuration_assignment(stripped)
            if key:
                key_lower = key.lower()
                value_lower = value.lower()
                if _looks_secret_name(key) and value:
                    self._add(_secret_rule_for([key], value), number, column, line, "configuration-token")
                if key_lower in {"debug", "flask_debug"} and value_lower == "true":
                    self._add("SAST_PY_DEBUG_MODE", number, column, line, "configuration-token")
                if key_lower in {"iv", "nonce"} and len(value) >= 8:
                    self._add("SAST_PY_STATIC_IV_NONCE", number, column, line, "configuration-token")
                if key_lower in {"rejectunauthorized", "node_tls_reject_unauthorized"} and value_lower in {"false", "0"}:
                    self._add("SAST_NODE_TLS_REJECT_UNAUTHORIZED_FALSE", number, column, line, "configuration-token")
                if key_lower in {"alg", "algorithm"} and value_lower == "none":
                    self._add("SAST_JWT_NONE", number, column, line, "configuration-token")
            if "TLSv1" in stripped or "TLS1.0" in stripped or "TLS1.1" in stripped:
                self._add("SAST_TLS_LEGACY_PROTOCOL", number, 1, line, "configuration-token")
            if "allow_origins" in stripped and "allow_credentials" in stripped and "*" in stripped and "true" in stripped.lower():
                self._add("SAST_FASTAPI_CORS_WILDCARD_CREDENTIALS", number, 1, line, "configuration-token")
        return self.matches

    def _add(self, rule_id: str, line: int, column: int, text: str, analyzer: str) -> None:
        self.matches.append(SemanticMatch(rule_id, line, max(column, 1), text, analyzer))


def _python_call_name(node: ast.AST | None, aliases: dict[str, str]) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Call):
        return _python_call_name(node.func, aliases)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _python_call_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _attribute_name(node: ast.AST) -> str:
    return _python_call_name(node, {})


def _assigned_names(node: ast.AST) -> Iterable[str]:
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            yield from _assigned_names(item)


def _literal_bool(node: ast.AST | None) -> bool | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, bool) else None


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value.decode("utf-8", errors="ignore")
    return ""


def _literal_int(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _python_is_tainted(node: ast.AST, tainted: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Attribute):
        path = _attribute_name(node)
        return path.startswith(("request.", "flask.request.", "self.request.")) or _python_is_tainted(node.value, tainted)
    if isinstance(node, ast.Subscript):
        return _python_is_tainted(node.value, tainted)
    if isinstance(node, ast.Call):
        return _python_call_name(node.func, {}).split(".")[0] in {"input", "getenv"} or any(_python_is_tainted(arg, tainted) for arg in node.args)
    if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
        return any(_python_is_tainted(child, tainted) for child in ast.iter_child_nodes(node))
    return False


def _python_sql_dynamic(node: ast.AST, tainted: set[str]) -> bool:
    return isinstance(node, (ast.BinOp, ast.JoinedStr)) or _python_is_tainted(node, tainted) or (isinstance(node, ast.Call) and _python_call_name(node, {}).endswith("format"))


def _is_sql_sink(name: str) -> bool:
    return name.split(".")[-1] in {"execute", "executeQuery", "query"}


def _is_path_sink(name: str) -> bool:
    return name.split(".")[-1] in {"open", "read_text", "read_bytes", "readFile", "createReadStream", "send_file", "send_from_directory"}


def _looks_auth_cookie(node: ast.Call) -> bool:
    first = _literal_string(node.args[0] if node.args else None).lower()
    return any(word in first for word in ("session", "token", "auth", "jwt"))


def _jwt_verification_disabled(node: ast.Call, keywords: dict[str, ast.AST]) -> bool:
    if _literal_bool(keywords.get("verify_signature")) is False:
        return True
    for arg in [*node.args, *keywords.values()]:
        if isinstance(arg, ast.Dict):
            for key, value in zip(arg.keys, arg.values):
                if _literal_string(key) == "verify_signature" and _literal_bool(value) is False:
                    return True
    return False


def _cors_is_permissive(node: ast.Call) -> bool:
    keywords = {item.arg: item.value for item in node.keywords if item.arg}
    origins = keywords.get("allow_origins")
    credentials = _literal_bool(keywords.get("allow_credentials"))
    if credentials is not True or not isinstance(origins, (ast.List, ast.Tuple)):
        return False
    return any(_literal_string(item) == "*" for item in origins.elts)


def _source_line(lines: list[str], line: int) -> str:
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _looks_security_name(value: str) -> bool:
    lowered = value.lower().replace("_", "")
    return any(term in lowered for term in ("token", "secret", "password", "passwd", "session", "nonce", "auth", "credential", "key", "jwt"))


def _looks_secret_name(value: str) -> bool:
    return _looks_security_name(value) or value.lower() in {"api_key", "private_key_id"}


def _secret_rule_for(names: list[str], value: str) -> str:
    key = " ".join(names).lower()
    if value.startswith("AKIA") and len(value) == 20:
        return "HARDCODED_AWS_ACCESS_KEY"
    if "private_key" in key or "privatekey" in key:
        return "SAST_GCP_SERVICE_ACCOUNT_KEY"
    if "jwt" in key:
        return "SAST_JWT_SECRET"
    if "api" in key and "key" in key:
        return "SAST_GENERIC_API_KEY"
    if value.startswith(("postgres://", "postgresql://", "mysql://", "mongodb://")):
        return "SAST_DATABASE_URL_PASSWORD"
    return "SAST_GENERIC_HARDCODED_SECRET"


class _PythonTokenAnalyzer:
    """Safe fallback for incomplete source.  It uses lexical tokens only."""

    def __init__(self, content: str):
        self.tokens = _lex_javascript(content)
        self.matches: list[SemanticMatch] = []

    def run(self) -> list[SemanticMatch]:
        for index, token in enumerate(self.tokens):
            if token.kind != "identifier":
                continue
            path = _token_path(self.tokens, index)
            line = " ".join(item.value for item in _line_tokens(self.tokens, token.line))
            if path == "hashlib.md5": self._add("WEAK_HASH_MD5_PY_HASHLIB", token, line)
            if path == "hashlib.sha1": self._add("WEAK_HASH_SHA1_PY_HASHLIB", token, line)
            if path == "random.random" and _looks_security_name(_assigned_name_before(self.tokens, index)):
                self._add("SAST_PY_RANDOM_TOKEN", token, line)
            if path.endswith("AES.new") and "MODE_ECB" in line:
                self._add("SAST_PY_WEAK_CIPHER_DES_RC4_ECB", token, line)
        return self.matches

    def _add(self, rule_id: str, token: Token, text: str) -> None:
        self.matches.append(SemanticMatch(rule_id, token.line, token.column, text, "python-token-fallback"))


def _lex_javascript(content: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    column = 1
    length = len(content)
    while index < length:
        char = content[index]
        if char in " \t\r":
            index += 1; column += 1; continue
        if char == "\n":
            index += 1; line += 1; column = 1; continue
        if char == "/" and index + 1 < length and content[index + 1] == "/":
            while index < length and content[index] != "\n": index += 1; column += 1
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "*":
            index += 2; column += 2
            while index + 1 < length and not (content[index] == "*" and content[index + 1] == "/"):
                if content[index] == "\n": line += 1; column = 1
                else: column += 1
                index += 1
            index += 2; column += 2; continue
        start_line, start_column = line, column
        if char.isalpha() or char in "_$":
            start = index
            while index < length and (content[index].isalnum() or content[index] in "_$"):
                index += 1; column += 1
            tokens.append(Token(content[start:index], "identifier", start_line, start_column)); continue
        if char.isdigit():
            start = index
            while index < length and (content[index].isalnum() or content[index] in ".xX"):
                index += 1; column += 1
            tokens.append(Token(content[start:index], "number", start_line, start_column)); continue
        if char in "'\"`":
            quote = char; index += 1; column += 1; start = index
            value: list[str] = []
            while index < length and content[index] != quote:
                if content[index] == "\\" and index + 1 < length:
                    value.append(content[index + 1]); index += 2; column += 2; continue
                value.append(content[index])
                if content[index] == "\n": line += 1; column = 1
                else: column += 1
                index += 1
            index += 1; column += 1
            tokens.append(Token("".join(value), "string", start_line, start_column)); continue
        tokens.append(Token(char, "symbol", start_line, start_column)); index += 1; column += 1
    return tokens


def _token_path(tokens: list[Token], index: int) -> str:
    parts = [tokens[index].value]; position = index + 1
    while position + 1 < len(tokens) and tokens[position].value == "." and tokens[position + 1].kind == "identifier":
        parts.append(tokens[position + 1].value); position += 2
    return ".".join(parts)


def _path_token_width(tokens: list[Token], index: int) -> int:
    width = 1; position = index + 1
    while position + 1 < len(tokens) and tokens[position].value == "." and tokens[position + 1].kind == "identifier": width += 2; position += 2
    return width


def _next_value(tokens: list[Token], index: int) -> str:
    return tokens[index].value if index < len(tokens) else ""


def _previous_value(tokens: list[Token], index: int) -> str:
    return tokens[index - 1].value if index else ""


def _next_string_or_number(tokens: list[Token], index: int) -> str:
    for token in tokens[index + 1:index + 10]:
        if token.kind in {"string", "number"}: return token.value
        if token.value == ";": break
    return ""


def _line_tokens(tokens: list[Token], line: int) -> list[Token]:
    return [token for token in tokens if token.line == line]


def _assigned_name_before(tokens: list[Token], index: int) -> str:
    position = index - 1
    while position >= 1:
        if tokens[position].value == "=" and tokens[position - 1].kind == "identifier": return tokens[position - 1].value
        if tokens[position].value in {";", "{"}: return ""
        position -= 1
    return ""


def _call_has_request_source(tokens: list[Token], index: int) -> bool:
    return _call_tokens(tokens, index).count("req") > 0 and any(value in _call_tokens(tokens, index) for value in ("query", "params", "body"))


def _call_has_dynamic_sql(tokens: list[Token], index: int) -> bool:
    values = _call_tokens(tokens, index)
    return "+" in values or "`" in values or any(value in values for value in ("req", "params", "query"))


def _call_tokens(tokens: list[Token], index: int) -> list[str]:
    position = index
    while position < len(tokens) and tokens[position].value != "(": position += 1
    depth = 0; values: list[str] = []
    while position < len(tokens):
        value = tokens[position].value; values.append(value)
        if value == "(": depth += 1
        if value == ")":
            depth -= 1
            if depth == 0: break
        position += 1
    return values


def _configuration_assignment(line: str) -> tuple[str, str, int]:
    delimiter = "=" if "=" in line else ":" if ":" in line else ""
    if not delimiter: return "", "", 1
    key, value = line.split(delimiter, 1)
    key = key.strip().strip("\"'")
    value = value.strip().strip("\"'")
    return key, value, line.find(delimiter) + 2


def _dedupe(matches: list[SemanticMatch]) -> list[SemanticMatch]:
    seen: set[tuple[str, int, int]] = set(); result: list[SemanticMatch] = []
    for item in matches:
        key = (item.rule_id, item.line_number, item.column_number)
        if key not in seen:
            seen.add(key); result.append(item)
    return result
