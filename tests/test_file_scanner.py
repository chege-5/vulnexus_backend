import pytest
from app.services.file_scanner import scan_file_content, compute_entropy


def test_detect_md5():
    code = '''
import hashlib
h = hashlib.md5(b"data")
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.uses_md5
    assert any(v.rule_id == "WEAK_HASH_MD5" for v in vulns)


def test_detect_sha1():
    code = '''
import hashlib
h = hashlib.sha1(b"data")
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.uses_sha1
    assert any(v.rule_id == "WEAK_HASH_SHA1" for v in vulns)


def test_detect_des():
    code = '''
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC)
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.uses_des
    assert any(v.rule_id == "WEAK_CIPHER_DES" for v in vulns)


def test_detect_ecb():
    code = '''
cipher = AES.new(key, AES.MODE_ECB)
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.uses_ecb
    assert any(v.rule_id == "WEAK_CIPHER_AES-ECB" for v in vulns)


def test_detect_small_rsa_key():
    code = '''
key = RSA.generate(bits=1024)
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.rsa_key_small
    assert any(v.rule_id == "SMALL_RSA_KEY" for v in vulns)


def test_detect_hardcoded_key():
    code = '''
secret_key = "c3VwZXJzZWNyZXRrZXkxMjM0NTY="
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.hardcoded_key
    assert any(v.rule_id == "HARDCODED_KEY" for v in vulns)


def test_detect_insecure_random():
    code = '''
import random
nonce = random.random()
'''
    vulns, features = scan_file_content(code, "test.py")
    assert features.insecure_random
    assert any(v.rule_id == "INSECURE_RANDOM" for v in vulns)


def test_clean_code_no_vulns():
    code = '''
import hashlib
h = hashlib.sha256(b"data")
'''
    vulns, features = scan_file_content(code, "test.py")
    assert len(vulns) == 0
    assert not features.uses_md5
    assert not features.uses_sha1


def test_entropy_computation():
    data = b"AAAAAAAAAA"
    e = compute_entropy(data)
    assert e == 0.0

    data2 = bytes(range(256))
    e2 = compute_entropy(data2)
    assert e2 > 7.9


def test_detect_private_key():
    code = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
'''
    vulns, features = scan_file_content(code, "key.pem")
    assert features.hardcoded_key
