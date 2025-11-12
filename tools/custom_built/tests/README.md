# tests — tools/custom-built

This folder contains lightweight smoke and extended tests for the `password_generator.py`
module in `tools/custom-built`. The tests are written with `pytest` and are intended
to be quick sanity checks (smoke tests) and small behavioural checks (extended tests)
so you can validate core functionality after changes.

## Layout

- `test_password_generator_smoke.py` — quick smoke tests that check:
  - module import and default random password generation
  - custom random length
  - basic memorable-passphrase generation (skipped if the EFF wordlist is missing)

- `test_password_generator_extended.py` — more focused checks:
  - length clamping for random passwords
  - printable, non-whitespace characters in random passwords
  - NFC normalization checks
  - invalid `pw_type` handling
  - memorable-passphrase validations (skipped when the EFF wordlist is missing)
  - a small cache test to ensure the wordlist loader caches the list object

## Prerequisites

- Python 3.9+ (the module uses `list[str]` type annotations and other modern features)
- `pytest` (install below)
- Project dependencies (if any) — use the repository `requirements.txt` if present.

Install pytest (recommended in a virtualenv):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -U pytest
# optionally install the project's requirements:
pip install -r [requirements.txt](http://_vscodecontentref_/1)