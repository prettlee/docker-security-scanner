"""Module entry point for `python3 -m dockscan.dockerfile`."""

import sys

from dockscan.dockerfile.cli import main

if __name__ == "__main__":
    sys.exit(main())
