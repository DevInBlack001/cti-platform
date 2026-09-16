"""Runs one pass: FLOD's database in, signed Threat Observations out."""

from __future__ import annotations

import sys

from collection.config import ConfigNotFoundError, resolve_flod_db_path
from collection.extractor import run
from collection.sources.flod import FlodConnector


def main() -> int:
    try:
        db_path = resolve_flod_db_path().value
    except ConfigNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 1

    connector = FlodConnector(db_path)
    written = run(connector)
    print(f"Wrote {written} observation(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
