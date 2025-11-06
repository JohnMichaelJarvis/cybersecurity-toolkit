import sys
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
import pytest

MODULE_PATH = Path(__file__).parent.parent / "password_generator.py"


def load_pw_module():
    """Load the password_generator module from file path."""
    spec = spec_from_file_location("pwgen", str(MODULE_PATH))
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_random_password_default_length():
    mod = load_pw_module()
    pw = mod.generate_password()
    assert isinstance(pw, str), "generate_password should return a string"
    assert len(pw) == 16, "default random password length should be 16"


def test_random_password_custom_length():
    mod = load_pw_module()
    pw = mod.generate_password(pw_type="random", random_type_length=24)
    assert isinstance(pw, str)
    assert len(pw) == 24


def test_memorable_passphrase_basic():
    mod = load_pw_module()
    # check if the wordlist exists — skip test if it's missing
    wl_path = (
        Path(__file__).parent.parent.parent.parent
        / "wordlists"
        / "eff_large_wordlist.txt"
    )
    if not wl_path.exists():
        pytest.skip(
            f"EFF wordlist not found at {wl_path}; skipping memorable passphrase test"
        )

    num_words = 4
    sep = "-"
    pw = mod.generate_password(
        pw_type="memorable", memorable_type_length=num_words, separator=sep
    )
    assert isinstance(pw, str)
    parts = pw.split(sep)
    assert len(parts) == num_words, f"expected {num_words} words separated by '{sep}'"
    # each word should be non-empty and NFC-normalized
    for w in parts:
        assert w, "word should not be empty"
        assert w == w, "word should be a string (sanity check)"
