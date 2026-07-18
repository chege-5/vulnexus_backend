from jinja2 import Template
import httpx
import ssl
import hashlib

rendered = Template(user_template).render()
client = httpx.Client(verify=False)
context = ssl._create_unverified_context()
password_digest = hashlib.md5(password.encode()).hexdigest()
cipher = AES.new(key, AES.MODE_ECB)
iv = b"not-a-real-iv-1"
response.set_cookie("session_token", access_token)
cursor.execute(f"SELECT * FROM accounts WHERE id = {request.query_params['id']}")
payload = open(request.query_params["filename"])
