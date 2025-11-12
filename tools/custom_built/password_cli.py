"""
Simple CLI wrapper for tools.custom-built.password_generator.generate_password

Usage examples:
  python password_cli.py --type random --random-length 20
  python password_cli.py --type memorable --words 4 --separator "-"
  python password_cli.py --type random --count 5 --copy
"""

from __future__ import annotations
import argparse
import sys
from typing import Optional
import shutil
import subprocess

from password_generator import generate_password  # relative import within same folder
# Do not import pyperclip at module import time; we'll import it lazily when --copy is used.


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="password_cli.py",
        description="Generate cryptographically-secure passwords or memorable passphrases.",
    )
    p.add_argument(
        "--type",
        "-t",
        choices=("random", "memorable"),
        default="random",
        help="Type of secret to generate (default: random).",
    )
    p.add_argument(
        "--random-length",
        "-r",
        type=int,
        default=16,
        help="Length for character-based passwords (min 8, max 64).",
    )
    p.add_argument(
        "--words",
        "-w",
        type=int,
        default=4,
        help="Number of words for memorable passphrases.",
    )
    p.add_argument(
        "--separator",
        "-s",
        default="-",
        help="Separator for memorable passphrases (default: '-')",
    )
    p.add_argument(
        "--unicode",
        action="store_true",
        dest="use_unicode",
        help="Include a small set of extra Unicode characters in character-based passwords.",
    )
    p.add_argument(
        "--count",
        "-c",
        type=int,
        default=1,
        help="Number of secrets to generate (default: 1).",
    )
    p.add_argument(
        "--copy",
        action="store_true",
        help="Copy the first generated secret to clipboard (requires pyperclip).",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    try:
        args = _parse_args(argv)
        if args.count < 1:
            print("Error: --count must be >= 1", file=sys.stderr)
            return 2

        results = []
        for _ in range(args.count):
            if args.type == "random":
                pw = generate_password(
                    use_unicode=args.use_unicode,
                    pw_type="random",
                    random_type_length=args.random_length,
                )
            else:
                pw = generate_password(
                    use_unicode=args.use_unicode,
                    pw_type="memorable",
                    memorable_type_length=args.words,
                    separator=args.separator,
                )
            results.append(pw)

        # Print each secret on its own line
        out = "\n".join(results)
        print(out)

        # Optional clipboard copy for the first item (import pyperclip only when requested)
        if args.copy:
            text = results[0]
            # Try pyperclip first
            try:
                import pyperclip  # type: ignore

                try:
                    pyperclip.copy(text)
                    print("First secret copied to clipboard.", file=sys.stderr)
                except Exception as e:
                    # pyperclip was present but failed to copy
                    print(f"Warning: pyperclip failed to copy: {e}", file=sys.stderr)
                    raise
            except Exception as e_py:
                # If pyperclip not available or it raised PyperclipException, try direct backends
                # Common Linux clipboard utilities:
                backends = [
                    ("xclip", ["xclip", "-selection", "clipboard"]),
                    ("xsel", ["xsel", "--clipboard", "--input"]),
                    ("wl-copy", ["wl-copy"]),
                ]
                used = False
                for name, cmd in backends:
                    if shutil.which(name):
                        try:
                            p = subprocess.run(cmd, input=text.encode(), check=True)
                            print(f"First secret copied using {name}.", file=sys.stderr)
                            used = True
                            break
                        except Exception as e_cmd:
                            print(
                                f"Warning: {name} found but copy failed: {e_cmd}",
                                file=sys.stderr,
                            )
                if not used:
                    # Provide actionable guidance for headless containers
                    print(
                        "Warning: clipboard copy unavailable. Typical causes:\n"
                        "- Missing clipboard tools in the container (install xclip/xsel/wl-clipboard),\n"
                        "- No X/Wayland DISPLAY available in headless container (clipboard requires a display),\n"
                        "- Running inside a Codespace/devcontainer without host clipboard forwarding.\n\n"
                        "To fix: install a backend in the container (e.g. `sudo apt-get install xclip`),\n"
                        "or skip --copy and capture output (redirect or pipe) instead.\n"
                        "If you need host clipboard access from Codespaces, use the editor/terminal copy features.\n",
                        file=sys.stderr,
                    )

        return 0
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
