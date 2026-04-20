import pytest
from llm_guard.input_scanners.secrets import Secrets

def test_tuya_secrets_redaction():
    scanner = Secrets()
    
    # Test Tuya Client ID
    prompt = "Tuya Client ID: v8u9n6x4h5y2p1z7q0w3"
    sanitized, is_safe, risk_score = scanner.scan(prompt)
    assert "******" in sanitized
    assert is_safe is False
    assert risk_score == 1.0

    # Test Tuya Client Secret
    prompt = "tuya_client_secret = 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b"
    sanitized, is_safe, risk_score = scanner.scan(prompt)
    assert "******" in sanitized
    assert is_safe is False
    assert risk_score == 1.0

    # Test negative case
    prompt = "This is a normal prompt without secrets."
    sanitized, is_safe, risk_score = scanner.scan(prompt)
    assert sanitized == prompt
    assert is_safe is True
