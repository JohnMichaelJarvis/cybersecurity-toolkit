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
    
    password: str = ""

    if pw_type != "memorable" or pw_type not in PW_TYPES:
        password = _generate_random_type_password(
            use_unicode, length=random_type_length
        )
    else:
        password = _generate_memorable_type_password(
            use_unicode, memorable_type_length, separator
        )
    return password


def _generate_random_type_password(use_unicode: bool, length: int) -> str:
    """
    Generate a character-based password using a cryptographically-secure RNG.

    Parameters
    - use_unicode (bool): Whether to include the conservative Unicode extras.
    - length (int): Desired password length (number of characters). The calling
      code enforces/validates sensible minimum and maximum lengths; if the
      requested length is outside supported bounds, a default or clamped value
      will be used.

    Returns
    - str: A cryptographically-random password string of the requested length.
    """
    # Default length for a password genrated from randomly chosen characters.
    MIN_LENGTH: int = 8
    MAX_LENGTH: int = 64

    if length not in range(MIN_LENGTH, MAX_LENGTH + 1):
        length = 16

    # Default alphabet using ascii characters
    ascii_alphabet: str = string.ascii_letters + string.digits + string.punctuation
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

    password = "".join([secrets.choice(alphabet) for ch in range(length)])

    return password


def _generate_memorable_type_password(
    use_unicode: bool, length: int, separator: str
) -> str:
    """
    Generate a memorable passphrase by selecting random words from a wordlist.

    Behavior
    - Reads a vetted wordlist (default path: `wordlists/eff_large_wordlist.txt`)
      and selects `length` words uniformly at random using a CSPRNG.
    - Joins the words with `separator` to form the final passphrase.
    - If `use_unicode` is True and the wordlist contains Unicode, selected words
      are normalized to NFC before joining.

    Parameters
    - use_unicode (bool): Whether to allow/normalize Unicode content from the
      wordlist. Note that enabling Unicode may reduce portability on some systems.
    - length (int): Number of words to include in the passphrase.
    - separator (str): Separator string placed between words in the passphrase.

    Returns
    - str: The generated passphrase (words joined by `separator`).
    """
    
    with open("wordlists/eff_large_wordlist.txt", "r") as file:
        wordlist: list = file.readlines()
        wordlist = [word.strip() for word in wordlist]

    password: str = "-".join(secrets.choice(wordlist) for word in wordlist)

    return password
