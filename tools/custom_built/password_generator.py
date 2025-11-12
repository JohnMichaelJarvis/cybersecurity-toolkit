"""
password_generator.py

A Python-based password and passphrase generator following NIST SP 800-63B recommendations for memorized secrets. This module generates cryptographically secure random secrets, prioritizing length and entropy over arbitrary composition rules.

Features:
- Uses Python's `secrets` module for secure random generation.
- Supports both character-based passwords and word-based passphrases.
- Favors longer secrets and multi-word passphrases for better security.
- Avoids enforcing unnecessary complexity requirements.

Security Best Practices:
- Prefer secrets with at least 8 characters; 12+ or multi-word passphrases are recommended.
- Check generated secrets against lists of compromised passwords.
- Never log or commit secrets; store them securely.
- Avoid exposing secrets in CLI history or logs.

References:
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html

Disclaimer:
- Review NIST SP 800-63B and organizational policies before production use.
"""

import secrets
import string
import unicodedata
import math
import logging
from pathlib import Path
from threading import Lock
import hashlib

_WORDLIST_LOCK: Lock = Lock()
_WORDLIST: list[str] | None = None
_ASCII_ALPHABET: str = string.ascii_letters + string.digits + string.punctuation


def generate_secret(
    use_unicode: bool = False,
    secret_type="password",
    password_length=16,
    passphrase_length=4,
    separator: str = "-",
) -> str:
    """
    Generate a password or passphrase.
    Returns a randomly-generated character password or a memorable word-based
    passphrase depending on the secret_type argument. Unicode is opt-in; output is
    normalized to NFC.

    Parameters
    - use_unicode (bool): If True, include a small conservative set of extra
      Unicode characters when generating character-based passwords. Default False
      for maximum portability.
    - secret_type (str): Type of secret to generate. Supported values:
      - "password": character-based password (default)
      - "passphrase": word-based passphrase drawn from a vetted wordlist
    - password_length (int): Length (number of characters) for password
      passwords. Defaults to 16. Values outside the supported range will be
      clamped by the underlying generator.
    - passphrase_length (int): Number of words for passphrases.
      Defaults to 4.
    - separator (str): String used to join words for passphrases.
      Default is "-".

    Returns
    - str: Generated secret (password or passphrase). The string is normalized
      (NFC) by the underlying generators to reduce combining-character issues.
    """

    SECRET_TYPES: set = {"password", "passphrase"}
    if secret_type not in SECRET_TYPES:
        raise ValueError(f"Unsupported secret_type: {secret_type!r}")
    if secret_type == "passphrase":
        secret_dict: dict = _generate_passphrase(
            use_unicode, passphrase_length, separator
        )
    else:
        secret_dict = _generate_password(use_unicode, length=password_length)

    secret: str = unicodedata.normalize("NFC", secret_dict["value"])

    if secret_dict.get("bits_entropy", 0.0) < 64.0:
        logging.warning(
            "Generated secret has a low entropy value of %f bits.",
            round(secret_dict.get("bits_entropy", 0.0), 2),
        )

    return secret


def _generate_password(use_unicode: bool, length: int) -> dict:
    """
    Generate a character-based password using a cryptographically-secure RNG.
    """
    MIN_LENGTH: int = 8
    MAX_LENGTH: int = 64

    length = max(MIN_LENGTH, min(length, MAX_LENGTH))

    global _ASCII_ALPHABET
    ascii_alphabet: str = _ASCII_ALPHABET

    if use_unicode:
        extra_unicode: str = "¡¢£¤¥§©®±µ¶•–—…°€†‡"
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

    secret_dict: dict = _build_secret_dictionary("password", password, alphabet)

    return secret_dict


def _generate_passphrase(use_unicode: bool, length: int, separator: str) -> dict:
    """
    Generate a passphrase by selecting random words from a wordlist.
    """
    MAX_MEM_WORDS = 12
    sep = separator

    if length < 1:
        raise ValueError("Passphrase length must be >= 1 ")
    elif length < 4:
        logging.warning("Passphrases with fewer than 4 words may be weak.")

    length = min(length, MAX_MEM_WORDS)

    wordlist: list[str] = _load_eff_wordlist()

    if not wordlist:
        raise ValueError("Wordlist is empty; cannot generate passphrase.")

    passphrase: str = sep.join(secrets.choice(wordlist) for _ in range(length))

    secret_dict: dict = _build_secret_dictionary(
        "passphrase", passphrase, wordlist=wordlist, separator=sep
    )

    return secret_dict


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


def _calculate_entropy(secret_dict) -> float:
    """Calculate the entropy of a generated secret."""

    type: str = secret_dict.get("type", "")
    alphabet: str = secret_dict.get("alphabet", "")
    password: str = secret_dict.get("value", "")
    separator: str = secret_dict.get("separator", "")
    wordlist: list[str] = secret_dict.get("wordlist", [])
    bits_entropy: float = 0.0

    if type == "password":
        unique_length: int = len(set(alphabet))
        secret_length: int = len(password)
        bits_entropy = secret_length * math.log2(unique_length)
    if type == "passphrase":
        words_used = secret_dict.get("value", "").split(separator)
        num_words: int = len(words_used)
        bits_entropy = num_words * math.log2(len(wordlist))

    return bits_entropy


def _build_secret_dictionary(
    secret_type: str,
    secret: str,
    alphabet: str = "",
    wordlist: list[str] = [],
    separator: str = "",
) -> dict:
    """
    Build a dictionary containing details about the generated secret.

    Parameters:
    - secret_type (str): The type of secret (e.g., "random" or "memorable").
    - value (str): The generated secret value.
    - alphabet (str, optional): The alphabet used for password generation (if applicable).
    - wordlist (list[str], optional): The wordlist used for passphrase generation (if applicable).

    Returns:
    - dict[str, str, str, float]: A dictionary with keys "type", "value", "alphabet", and "bits_entropy".
    """

    secret_dict: dict = {
        "type": secret_type,
        "value": secret,
        "alphabet": alphabet,
        "wordlist": wordlist,
        "separator": separator,
        "bits_entropy": 0.0,
    }

    secret_dict["bits_entropy"] = _calculate_entropy(secret_dict)

    return secret_dict


def check_if_pwned(password: str) -> bool:
    """
    Check if a password has been exposed in a data breach.
    """
    import requests

    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        # Query the Pwned Passwords API (k-anonymity model)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        # Check if suffix appears in response
        hashes = (line.split(":") for line in response.text.splitlines())
        return any(suffix == hash_suffix for hash_suffix, _ in hashes)
    except requests.RequestException:
        logging.warning("Unable to check password against breach database")
        return False
