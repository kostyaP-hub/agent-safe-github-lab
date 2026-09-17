from __future__ import annotations

import argparse
import json
import sys

from .scanner import GateError, scan_directory


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a read-only static admission receipt. It never executes input."
    )
    parser.add_argument("path", help="Directory to inspect without following symlinks")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable receipt")
    args = parser.parse_args()

    try:
        receipt = scan_directory(args.path)
    except GateError as error:
        print(f"gate: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"verdict: {receipt['verdict']}")
        print(f"files scanned: {receipt['files_scanned']}")
        for finding in receipt["findings"]:
            location = finding["path"]
            if finding["line"] is not None:
                location = f"{location}:{finding['line']}"
            print(f"- [{finding['severity']}] {finding['category']} at {location}")
        print("Static review does not authorize execution.")
    return 0 if receipt["verdict"] == "STATIC_REVIEW_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
