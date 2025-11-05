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


