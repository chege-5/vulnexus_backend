from Crypto.Cipher import AES, DES3, ARC4
from cryptography.hazmat.primitives.asymmetric import rsa


key = b"0123456789abcdef"
iv = b"0000000000000000"
cipher = AES.new(key, AES.MODE_ECB)
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
legacy_des = DES3.new(b"0123456789abcdef01234567", DES3.MODE_CBC, iv)
stream_cipher = ARC4.new(b"weak-demo-key")
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
