"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc:
    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và allow=False.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str  # "public" | "internal" | "restricted"
    request_purpose: str      # ví dụ "reconciliation", "summarize-tickets"
    agent_owner: str          # định danh agent/run gọi tool
    delegation_depth: int     # 0 = trực tiếp, >0 = qua delegation
    egress_enabled: bool      # có quyền gọi network hay không


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật trước khi thực thi tool.
    
    Quy tắc tối thiểu bắt buộc:
    - data_classification == 'restricted' and egress_enabled is True -> DENY
    - Mọi quyết định (Allow hay Deny) đều phải kèm reason chi tiết.
    """
    # Rule 1: Chặn gửi dữ liệu nhạy cảm (restricted) ra ngoài mạng (egress)
    if context.data_classification == "restricted" and context.egress_enabled:
        return (
            False,
            f"Từ chối quyền egress cho dữ liệu '{context.data_classification}' "
            f"(agent: {context.agent_owner}, purpose: {context.request_purpose})"
        )

    # Rule 2: Cho phép các thao tác nội bộ hợp lệ
    return (
        True,
        f"Chấp thuận thao tác hợp lệ cho agent '{context.agent_owner}' "
        f"(classification: {context.data_classification}, egress: {context.egress_enabled}, "
        f"purpose: {context.request_purpose})"
    )
