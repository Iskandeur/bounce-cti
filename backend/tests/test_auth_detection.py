"""Unit tests for CLI auth-failure detection (distinct from quota)."""
from backend import agent_runner as ar


def test_detect_auth_error_matches_401_variants():
    assert ar._detect_auth_error("Failed to authenticate. API Error: 401 Invalid authentication credentials")
    assert ar._detect_auth_error("oauth token has expired, please run /login")
    assert ar._detect_auth_error("API ERROR: 401 INVALID")  # case-insensitive


def test_detect_auth_error_ignores_normal_text():
    assert not ar._detect_auth_error("added node domain evil.com")
    assert not ar._detect_auth_error("Claude AI usage limit reached|1700000000")  # quota, not auth
    assert not ar._detect_auth_error("")


def test_auth_not_confused_with_quota():
    # A quota marker must NOT register as an auth error (separate handling).
    quota = "You've reached your usage limit"
    assert not ar._detect_auth_error(quota)
