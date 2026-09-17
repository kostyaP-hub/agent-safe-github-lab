"""Read-only static admission receipt generator for the learning lab."""

from .scanner import GateError, scan_directory

__all__ = ["GateError", "scan_directory"]
