"""Module entry point for `python3 -m dockscan`."""

import sys

from dockscan.scanner import main

if __name__ == "__main__":
    sys.exit(main())
