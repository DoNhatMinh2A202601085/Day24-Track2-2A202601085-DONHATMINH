"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Interface:
    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
    redact(text: str) -> str
        Thay thế mọi entity bằng "[REDACTED_<TYPE>]"
"""
from __future__ import annotations

import re

# Regex định dạng
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_STK_PREFIX_RE = re.compile(r"(?:STK|số\s+tài\s+khoản|tài\s+khoản|stk)\s*[:.]?\s*(\d{8,19})\b", re.IGNORECASE)
_CCCD_PREFIX_RE = re.compile(r"(?:CCCD|căn\s+cước|cmnd)\s*[:.]?\s*(\d{12})\b", re.IGNORECASE)
_PHONE_PREFIX_RE = re.compile(r"(?:SĐT|SDT|số\s+điện\s+thoại|phone|hotline|là)\s*[:.]?\s*(0\d{9,10})\b", re.IGNORECASE)
_GENERIC_CCCD_RE = re.compile(r"\b\d{12}\b")
_GENERIC_PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản tiếng Việt."""
    entities: list[dict] = []
    occupied_spans: list[tuple[int, int]] = []

    def _add_entity(ent_type: str, start: int, end: int):
        # Kiểm tra không overlap với span đã có
        for s, e in occupied_spans:
            if not (end <= s or start >= e):
                return
        occupied_spans.append((start, end))
        entities.append({"type": ent_type, "start": start, "end": end})

    # 1. EMAIL
    for m in _EMAIL_RE.finditer(text):
        _add_entity("EMAIL", m.start(), m.end())

    # 2. VN_BANK_ACCOUNT (Ưu tiên nhận diện theo tiền tố STK/số tài khoản)
    for m in _STK_PREFIX_RE.finditer(text):
        # Lấy offset của nhóm capture chỉ chứa số
        start, end = m.span(1)
        _add_entity("VN_BANK_ACCOUNT", start, end)

    # 3. VN_CCCD (Ưu tiên theo tiền tố CCCD)
    for m in _CCCD_PREFIX_RE.finditer(text):
        start, end = m.span(1)
        _add_entity("VN_CCCD", start, end)

    # 4. VN_PHONE (Ưu tiên theo tiền tố SĐT)
    for m in _PHONE_PREFIX_RE.finditer(text):
        start, end = m.span(1)
        _add_entity("VN_PHONE", start, end)

    # 5. Fallback VN_CCCD (12 chữ số chưa bị chiếm)
    for m in _GENERIC_CCCD_RE.finditer(text):
        _add_entity("VN_CCCD", m.start(), m.end())

    # 6. Fallback VN_PHONE (10 chữ số bắt đầu bằng 0 chưa bị chiếm)
    for m in _GENERIC_PHONE_RE.finditer(text):
        _add_entity("VN_PHONE", m.start(), m.end())

    # Sắp xếp theo vị trí xuất hiện
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>]."""
    ents = detect(text)
    if not ents:
        return text

    # Sắp xếp ngược từ cuối về đầu để không làm lệch offset
    ents_reversed = sorted(ents, key=lambda x: x["start"], reverse=True)
    res = text
    for e in ents_reversed:
        tag = f"[REDACTED_{e['type']}]"
        res = res[:e["start"]] + tag + res[e["end"]:]
    return res
