"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

Interface:
    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _calc_hash(entry_without_hash: dict) -> str:
    payload = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi vào audit ledger theo cơ chế Hash Chain (SHA-256)."""
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash

    # Tính hash của record (không bao gồm trường 'hash')
    to_hash = {k: v for k, v in record.items() if k != "hash"}
    record["hash"] = _calc_hash(to_hash)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác thực tính toàn vẹn của chuỗi hash và các điều kiện bắt buộc trong ledger."""
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Kiểm tra trường reason bắt buộc phải non-empty
        reason = entry.get("reason")
        if not reason or not isinstance(reason, str) or not reason.strip():
            return False

        # 2. Kiểm tra prev_hash có khớp với dòng trước không
        if entry.get("prev_hash") != expected_prev:
            return False

        # 3. Kiểm tra tính toán lại hash có khớp không
        stored_hash = entry.get("hash")
        to_hash = {k: v for k, v in entry.items() if k != "hash"}
        calculated_hash = _calc_hash(to_hash)
        if stored_hash != calculated_hash:
            return False

        expected_prev = stored_hash

    return True
