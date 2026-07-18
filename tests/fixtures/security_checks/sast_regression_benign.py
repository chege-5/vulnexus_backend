from jinja2 import Environment, select_autoescape
import httpx
import ssl
import hashlib
from pathlib import Path

templates = Environment(autoescape=select_autoescape(("html", "xml")))
client = httpx.Client(verify=True)
context = ssl.create_default_context()
checksum = hashlib.md5(payload).hexdigest()  # checksum only, not security
response.set_cookie("session_token", access_token, secure=True, httponly=True, samesite="lax")
safe_path = Path(base_dir) / "public" / filename
cursor.execute("SELECT * FROM accounts WHERE id = %s", (account_id,))
