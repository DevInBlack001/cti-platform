"""Entry point for the collection pipeline.

Orchestrates a single collection pass: locate the FLOD database, connect to it,
extract signals, build and sign observations, and write them to the sink file.
Returns 0 on success, 1 if configuration is missing or the database is
inaccessible.
"""

from __future__ import annotations

import sys

from collection.config import ConfigNotFoundError, resolve_flod_db_path
from collection.extractor import run
from collection.sources.flod import FlodConnector, SymlinkDatabaseError


def main() -> int:
    """Executes one collection pass.

    Returns 0 if observations were written, 1 if configuration is missing or
    the database cannot be accessed (symlink, missing, or permission denied).
    """
    try:
        db_path = resolve_flod_db_path().value
    except ConfigNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 1

    connector = FlodConnector(db_path)
    try:
        written = run(connector)
    except (SymlinkDatabaseError, FileNotFoundError, PermissionError) as error:
        print(str(error), file=sys.stderr)
        return 1

    print(f"Wrote {written} observation(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
