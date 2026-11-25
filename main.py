"""Convenience entry point for running the Docker security scanner."""

import sys

from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
