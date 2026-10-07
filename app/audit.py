"""Hash-chained audit log. Each entry stores sha256(prev_hash + event +
detail + timestamp), so editing or deleting a past entry breaks the chain
for every entry after it — tampering becomes detectable via verify_chain()."""
import hashlib
from app.db import get_db

GENESIS_HASH = "0" * 64


def _hash_entry(prev_hash: str, event: str, detail: str, created_at: str) -> str:
    payload = f"{prev_hash}|{event}|{detail}|{created_at}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def log_event(event: str, detail: str = "", user_id: int | None = None, ip: str | None = None):
    db = get_db()
    row = db.execute(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS_HASH

    created_at_row = db.execute("SELECT datetime('now') AS now").fetchone()
    created_at = created_at_row["now"]

    entry_hash = _hash_entry(prev_hash, event, detail, created_at)
    db.execute(
        "INSERT INTO audit_log (event, detail, user_id, ip, created_at, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (event, detail, user_id, ip, created_at, prev_hash, entry_hash),
    )
    db.commit()


def verify_chain() -> tuple[bool, str]:
    """Recomputes the hash chain from genesis and reports the first break, if any."""
    db = get_db()
    rows = db.execute(
        "SELECT id, event, detail, created_at, prev_hash, entry_hash FROM audit_log ORDER BY id ASC"
    ).fetchall()

    expected_prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return False, f"Chain broken at audit_log.id={row['id']} (prev_hash mismatch)"
        recomputed = _hash_entry(row["prev_hash"], row["event"], row["detail"] or "", row["created_at"])
        if recomputed != row["entry_hash"]:
            return False, f"Chain broken at audit_log.id={row['id']} (entry tampered)"
        expected_prev = row["entry_hash"]

    return True, f"OK — {len(rows)} entries verified"
