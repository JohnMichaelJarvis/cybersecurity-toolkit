"""
password_generator.py

A Python-based password and passphrase generator designed to follow current NIST
recommendations for memorized secrets (see NIST SP 800-63B). This module produces
cryptographically-secure random secrets and favors length and entropy over
arbitrary, predictable composition rules.

Highlights
- Uses a cryptographically secure random source (e.g., the `secrets` module).
- Encourages longer secrets and passphrases instead of short, complex patterns.
- Avoids enforcing arbitrary composition requirements unless required by policy.
- Includes options for character-based secrets and word-based passphrases.

Security notes and best practices
- Prefer longer secrets (NIST encourages allowing long memorized secrets);
  consider a minimum of 8 characters but recommend 12+ characters or multi-word
  passphrases for interactive use.
- Screen generated and user-supplied secrets against known-bad lists of commonly
  used or compromised passwords.
- Never log secrets or commit them to source control; store them in secure vaults
  when needed.
- If exposing a CLI, avoid writing secrets to shell history or persistent logs.

References
- NIST Special Publication 800-63B, "Digital Identity Guidelines: Authentication and Lifecycle"
  — https://pages.nist.gov/800-63-3/sp800-63b.html

Disclaimer
- This docstring summarizes best-practice guidance inspired by NIST. Before
  deploying in production, review NIST SP 800-63B and your organization's
  security policies and consult security experts as needed.
"""

import secrets
import string
import unicodedata
from pathlib import Path
import logging
from threading import Lock

_WORDLIST_LOCK: Lock = Lock()
_WORDLIST: list[str] | None = None
_ASCII_ALPHABET: str = string.ascii_letters + string.digits + string.punctuation


def generate_password(
    use_unicode: bool = False,
    pw_type="random",
    random_type_length=16,
    memorable_type_length=4,
    separator: str = "-",
) -> str:
    """
    Generate a password or passphrase.
    Returns a randomly-generated character password or a memorable word-based
    passphrase depending on the pw_type argument. Unicode is opt-in; output is
    normalized to NFC.

    Parameters
    - use_unicode (bool): If True, include a small conservative set of extra
      Unicode characters when generating character-based passwords. Default False
      for maximum portability.
    - pw_type (str): Type of password to generate. Supported values:
      - "random": character-based password (default)
      - "memorable": word-based passphrase drawn from a vetted wordlist
    - random_type_length (int): Length (number of characters) for random type
      passwords. Defaults to 16. Values outside the supported range will be
      clamped by the underlying generator.
    - memorable_type_length (int): Number of words for memorable passphrases.
      Defaults to 4.
    - separator (str): String used to join words for memorable passphrases.
      Default is "-".

    Returns
    - str: Generated secret (password or passphrase). The string is normalized
      (NFC) by the underlying generators to reduce combining-character issues.
    """

    PW_TYPES: set = {"random", "memorable"}
    if pw_type not in PW_TYPES:
        raise ValueError(f"Unsupported pw_type: {pw_type!r}")
    if pw_type == "memorable":
        password: str = _generate_memorable_type_password(
            use_unicode, memorable_type_length, separator
        )
    else:
        password = _generate_random_type_password(
            use_unicode, length=random_type_length
        )

    password = unicodedata.normalize("NFC", password)

    return password


def _generate_random_type_password(use_unicode: bool, length: int) -> str:
    """
    Generate a character-based password using a cryptographically-secure RNG.
    """
    # Set bounds on password length.
    MIN_LENGTH: int = 8
    MAX_LENGTH: int = 64

    # Ensure user-provided length is within bounds.
    length = max(MIN_LENGTH, min(length, MAX_LENGTH))

    # Default alphabet using ascii characters
    global _ASCII_ALPHABET
    ascii_alphabet: str = _ASCII_ALPHABET

    if use_unicode:
        # Conservative, vetted extra characters (currency/math/typographic symbols).
        # Keep this small to reduce compatibility issues; adjust as needed.
        extra_unicode: str = "¡¢£¤¥§©®±µ¶•–—…°€†‡"
        # Normalize and filter to printable, non-space characters
        extra_filtered: str = "".join(
            ch
            for ch in unicodedata.normalize("NFC", extra_unicode)
            if ch.isprintable() and not ch.isspace()
        )
        alphabet = ascii_alphabet + extra_filtered
    else:
        alphabet = ascii_alphabet

    if not alphabet:
        raise ValueError("Alphabet is empty; check configuration or wordlist.")

    password = "".join([secrets.choice(alphabet) for _ in range(length)])

    password = unicodedata.normalize("NFC", password)

    return password


def _generate_memorable_type_password(
    use_unicode: bool, length: int, separator: str
) -> str:
    """
    Generate a memorable passphrase by selecting random words from a wordlist.

    """
    MAX_MEM_WORDS = 12

    if length < 1:
        raise ValueError("Memorable passphrase length must be >= 1 ")
    elif length < 4:
        logging.warning("Memorable passphrases with fewer than 4 words may be weak.")

    length = min(length, MAX_MEM_WORDS)

    wordlist: list[str] = _load_eff_wordlist()

    if len(wordlist) == 0:
        raise ValueError("Wordlist is empty; cannot generate memorable passphrase.")

    password: str = separator.join(secrets.choice(wordlist) for _ in range(length))

    return password


def _load_eff_wordlist() -> list[str]:
    """
    Load and cache the EFF wordlist. Returns a list of words (NFC-normalized).
    Raises FileNotFoundError if the file is missing.
    """
    global _WORDLIST
    with _WORDLIST_LOCK:
        if _WORDLIST is not None:
            return _WORDLIST

        wl_path = (
            Path(__file__).parent.parent.parent / "wordlists" / "eff_large_wordlist.txt"
        )
        words: list[str] = []
        try:
            with wl_path.open("r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    # support lines like "12345 word" -> take last token
                    word = s.split()[-1]
                    word = unicodedata.normalize("NFC", word)
                    words.append(word)
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist not found at expected path: {wl_path!r}")

        if not words:
            raise ValueError("Loaded wordlist is empty; check the wordlist file.")

        _WORDLIST = words

        return _WORDLIST
