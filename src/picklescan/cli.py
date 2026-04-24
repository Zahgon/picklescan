import argparse
import logging
import os
import re
import sys

from .scanner import ScanFilter, ScanResult, scan_directory_path
from .scanner import scan_file_path
from .scanner import scan_url
from .scanner import scan_huggingface_model

_log = logging.getLogger("picklescan")


def print_summary(show_globals: bool, sr: ScanResult):
    pass


def main():
    pass


if __name__ == "__main__":
    sys.exit(main())
