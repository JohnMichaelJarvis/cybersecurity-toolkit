from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
import unicodedata
import pytest

MODULE_PATH = Path(__file__).parent.parent / "password_generator.py"


def load_pw_module():
    """Load the password_generator module from file path (fresh import each call)."""
    spec = spec_from_file_location("pwgen", str(MODULE_PATH))
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_random_length_clamping():
    mod = load_pw_module()
    # requested length below minimum (1) should be clamped to 8
    pw = mod.generate_password(pw_type="random", random_type_length=1)
    assert isinstance(pw, str)
    assert len(pw) == 8


def test_random_password_printable_and_no_whitespace():
    mod = load_pw_module()
    pw = mod.generate_password()
    assert all(c.isprintable() and not c.isspace() for c in pw), (
        "password should contain printable, non-whitespace characters"
    )


def test_random_password_normalized_nfc():
    mod = load_pw_module()
    pw = mod.generate_password()
    assert pw == unicodedata.normalize("NFC", pw), "password should be NFC-normalized"


def test_invalid_pw_type_raises():
    mod = load_pw_module()
    with pytest.raises(ValueError):
        mod.generate_password(pw_type="no-such-type")


def test_memorable_length_validation_and_wordcount():
    """
    Memorable-passphrase tests only run if the EFF wordlist exists in the repo.
    Otherwise skip.
    """
    mod = load_pw_module()
    wl_path = (
        Path(__file__).parent.parent.parent.parent
        / "wordlists"
        / "eff_large_wordlist.txt"
    )
    if not wl_path.exists():
        pytest.skip(
            f"EFF wordlist not found at {wl_path}; skipping memorable-passphrase checks"
        )

    # invalid length (0) should raise (module requires length >= 1)
    with pytest.raises(ValueError):
        mod.generate_password(pw_type="memorable", memorable_type_length=0)

    # valid generation: request 5 words and check word count
    num_words = 5
    sep = " "
    pw = mod.generate_password(
        pw_type="memorable", memorable_type_length=num_words, separator=sep
    )
    assert isinstance(pw, str)
    parts = pw.split(sep)
    assert len(parts) == num_words, f"expected {num_words} words separated by '{sep}'"


def test_wordlist_cached_after_first_load():
    mod = load_pw_module()
    wl_path = (
        Path(__file__).parent.parent.parent.parent
        / "wordlists"
        / "eff_large_wordlist.txt"
    )
    if not wl_path.exists():
        pytest.skip("Wordlist missing; skip cache test")
    # If wordlist exists, _load_eff_wordlist should return the same cached object on subsequent calls
    first = mod._load_eff_wordlist()
    second = mod._load_eff_wordlist()
    assert first is second, (
        "wordlist loader should cache the loaded list (same object returned)"
    )
