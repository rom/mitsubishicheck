"""
Main entry point for running mitsubishicheck as a module.

Usage:
    python -m mitsubishicheck [args]
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
