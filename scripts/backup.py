#!/usr/bin/env python3
"""SENTINEL-M local backup tool (Phase 7).

Produces a consistent copy of the SQLite database using the online backup API
(checkpoints the WAL into the copy), so the backup is valid even while the
server is running. The audit chain and event/alert data are included; the
secret key and token material are NOT part of this backup (they live in the
environment/.env and must be preserved separately by the operator).

Usage:
    python scripts/backup.py [--data-dir backend/data] [--out backups/]
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DB = _REPO_ROOT / "backend" / "data" / "sentinel.db"


def backup(db_path: Path, out_dir: Path) -> Path:
    if not db_path.exists():
        raise SystemExit(f"database not found: {db_path}")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = out_dir / f"sentinel-backup-{stamp}.db"
    # online backup API: copies WAL + main DB into one consistent file
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    dst = sqlite3.connect(dest)
    try:
        with dst:
            src.backup(dst)
    finally:
        dst.close()
        src.close()
    # sanity: the copy must open and expose the core tables
    probe = sqlite3.connect(dest)
    try:
        tables = {r[0] for r in probe.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        expected = {"events", "alerts", "incidents", "assets", "audit_log"}
        missing = expected - tables
        if missing:
            dest.unlink(missing_ok=True)
            raise SystemExit(f"backup incomplete (missing tables: {sorted(missing)})")
    finally:
        probe.close()
    return dest


def prune(out_dir: Path, keep: int) -> None:
    """Keep the newest N backups, delete older ones (rolling backup policy)."""
    files = sorted(out_dir.glob("sentinel-backup-*.db"), reverse=True)
    for old in files[keep:]:
        old.unlink()


def main() -> int:
    ap = argparse.ArgumentParser(description="Back up the SENTINEL-M database")
    ap.add_argument("--data-dir", default=str(_DEFAULT_DB.parent),
                    help="directory containing sentinel.db")
    ap.add_argument("--db", default="", help="explicit sqlite file path")
    ap.add_argument("--out", default=str(_REPO_ROOT / "backups"),
                    help="backup destination directory")
    ap.add_argument("--keep", type=int, default=7,
                    help="rolling retention: keep the newest N backups (0 = keep all)")
    args = ap.parse_args()

    db_path = Path(args.db) if args.db else Path(args.data_dir) / "sentinel.db"
    dest = backup(db_path, Path(args.out))
    if args.keep > 0:
        prune(Path(args.out), args.keep)
    size_kb = dest.stat().st_size // 1024
    print(f"backup written: {dest} ({size_kb} kB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())