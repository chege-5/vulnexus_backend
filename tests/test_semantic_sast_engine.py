from __future__ import annotations

import inspect
import ast

from app.services.file_scanner import scan_file_content
from app.services import file_scanner, semantic_engine


def test_python_ast_dataflow_tracks_request_input_to_sql_sink() -> None:
    findings, _ = scan_file_content(
        """
user_id = request.query_params['id']
query = f\"SELECT * FROM accounts WHERE id = {user_id}\"
cursor.execute(query)
""",
        "routes.py",
    )
    finding = next(item for item in findings if item.rule_id == "SAST_SQL_CONCAT")
    assert finding.evidence["analysis_engine"] == "python-taint"
    assert finding.line_number == 4
    assert finding.column_number


def test_javascript_token_analysis_handles_multiline_function_scope() -> None:
    findings, _ = scan_file_content(
        """
function issueResetToken() {
  const suffix = Math.random()
  return suffix
}
""",
        "auth.js",
    )
    assert any(item.rule_id == "SAST_JS_MATH_RANDOM_TOKEN" for item in findings)


def test_sast_detection_path_never_compiles_or_executes_regular_expressions() -> None:
    for module in (file_scanner, semantic_engine):
        imports = [node for node in ast.walk(ast.parse(inspect.getsource(module))) if isinstance(node, (ast.Import, ast.ImportFrom))]
        assert all("re" not in [alias.name for alias in node.names] for node in imports)
    assert "compiled_regex" not in inspect.getsource(semantic_engine)
