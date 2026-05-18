from worker.normalize.redact import redact, safe_for_llm


def test_redacts_aws_access_key():
    s = "creds: AKIAABCDEFGHIJKLMNOP something"
    out = redact(s)
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert "AKIA" in out  # masked form retains the prefix


def test_redacts_github_token():
    s = "token=ghp_" + "a" * 36
    assert "ghp_" + "a" * 36 not in redact(s)


def test_redacts_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9." + "a" * 20 + "." + "b" * 20
    assert jwt not in redact(jwt)


def test_redacts_private_key_block():
    s = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\nafter"
    out = redact(s)
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert "before" in out and "after" in out


def test_redacts_host_path():
    out = redact("error at /Users/alice/project/secret.py line 10")
    assert "/Users/alice" not in out


def test_redacts_internal_ip():
    assert "10.0.0.1" not in redact("internal=10.0.0.1")


def test_safe_for_llm_caps_length():
    out = safe_for_llm("x" * 5000)
    assert len(out) <= 400
