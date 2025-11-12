import unicodedata
import pytest
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "password_generator.py"


def load_pw_module():
    """Load the password_generator module from file path."""
    spec = spec_from_file_location("pwgen", str(MODULE_PATH))
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generate_secret_password_default_length():
    mod = load_pw_module()
    pw = mod.generate_secret(secret_type="password")
    assert isinstance(pw, str)
    assert len(pw) == 16


def test_generate_secret_password_custom_length():
    mod = load_pw_module()
    pw = mod.generate_secret(secret_type="password", password_length=24)
    assert len(pw) == 24


def test_generate_secret_passphrase_default_separator():
    try:
        mod = load_pw_module()
        pw = mod.generate_secret(secret_type="passphrase", passphrase_length=4)
    except FileNotFoundError:
        pytest.skip("Wordlist not available for passphrase test")
    assert "-" in pw


def test_generate_secret_passphrase_custom_separator():
    try:
        mod = load_pw_module()
        pw = mod.generate_secret(
            secret_type="passphrase", passphrase_length=3, separator="*"
        )
    except FileNotFoundError:
        pytest.skip("Wordlist not available for passphrase test")
    assert "*" in pw


def test_generate_secret_invalid_type_raises():
    with pytest.raises(ValueError):
        mod = load_pw_module()
        mod.generate_secret(secret_type="invalid")


def test_password_is_nfc_normalized():
    mod = load_pw_module()
    pw = mod.generate_secret(secret_type="password")
    assert pw == unicodedata.normalize("NFC", pw)


def test_entropy_warning_for_low_entropy(caplog: pytest.LogCaptureFixture):
    # Generate a password with very low entropy
    mod = load_pw_module()
    mod.generate_secret(secret_type="password", password_length=1)
    assert "low entropy" in caplog.text.lower()


def test_passphrase_word_count():
    try:
        mod = load_pw_module()
        pw = mod.generate_secret(
            secret_type="passphrase", passphrase_length=5, separator=" "
        )
    except FileNotFoundError:
        pytest.skip("Wordlist not available for passphrase test")
    assert len(pw.split(" ")) == 5


def test_generate_secret_passphrase_minimum_length():
    try:
        mod = load_pw_module()
        pw = mod.generate_secret(secret_type="passphrase", passphrase_length=1)
    except FileNotFoundError:
        pytest.skip("Wordlist not available for passphrase test")
    assert isinstance(pw, str) and len(pw) > 0


def test_generate_secret_password_uniqueness():
    mod = load_pw_module()
    passwords = [
        mod.generate_secret(secret_type="password", password_length=16)
        for _ in range(50)
    ]
    assert len(set(passwords)) > 45
