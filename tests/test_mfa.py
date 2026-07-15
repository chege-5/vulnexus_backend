from app.services.mfa import consume_recovery_code, generate_recovery_codes, generate_totp_secret, provisioning_uri, verify_totp, _totp


def test_totp_secret_uri_and_verification_are_compatible():
    secret = generate_totp_secret()
    uri = provisioning_uri(secret=secret, account_name="user@example.com")
    code = _totp(secret, 123456)

    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    assert verify_totp(secret, code, now=123456 * 30)
    assert not verify_totp(secret, "000000", now=123456 * 30)


def test_recovery_codes_are_hashed_and_consumed_once():
    codes, hashes = generate_recovery_codes(count=2)

    assert codes[0] not in hashes
    accepted, remaining = consume_recovery_code(hashes, codes[0])
    assert accepted
    accepted_again, _ = consume_recovery_code(remaining, codes[0])
    assert not accepted_again
