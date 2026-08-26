"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt:
    Run A: gọi search_docs (untrusted content). Không gọi read_customer, không gọi http_post.
    Run B: gọi read_customer (private data). CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A
           (list[int] ticket id trích từ TÊN FILE). Tra cứu customer_id qua related_tickets.

Mọi tool call đều qua policy.check() và được ghi vào ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _hash_args(data: object) -> str:
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Xử lý yêu cầu người dùng theo mô hình Trifecta Split và Policy Enforcement."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"

    # -------------------------------------------------------------
    # RUN A: Đọc untrusted content từ corpus/
    # -------------------------------------------------------------
    search_ctx = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-ticket-docs",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    search_allow, search_reason = policy.check(search_ctx)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-governed-agent",
            "run_id": run_a_id,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": search_ctx.data_classification,
            "decision": "allow" if search_allow else "deny",
            "reason": search_reason,
        },
        ledger_path,
    )

    if not search_allow:
        return "Yêu cầu tìm kiếm tài liệu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    # Trích xuất dữ liệu typed (ticket IDs từ tên file) - KHÔNG tin free text
    ticket_ids: list[int] = []
    for d in docs:
        match = re.search(r"ticket-(\d+)", d.get("id", ""))
        if match:
            ticket_ids.append(int(match.group(1)))

    # Kiểm tra xem có dấu hiệu injection trong nội dung không (để log audit)
    injected = llm.find_injection(combined_text)

    # -------------------------------------------------------------
    # RUN B: Đọc private data từ nguồn tin cậy (customers.json)
    # -------------------------------------------------------------
    customers_data = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_to_customers: dict[int, list[str]] = {}
    for cust in customers_data:
        cid = cust["customer_id"]
        for tid in cust.get("related_tickets", []):
            ticket_to_customers.setdefault(tid, []).append(cid)

    # Tìm customer_ids từ ticket_ids hợp lệ
    trusted_customer_ids: set[str] = set()
    for tid in ticket_ids:
        if tid in ticket_to_customers:
            trusted_customer_ids.update(ticket_to_customers[tid])

    # Thực hiện gọi read_customer cho các khách hàng hợp lệ
    for cid in sorted(trusted_customer_ids):
        read_ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="read-customer-details",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        read_allow, read_reason = policy.check(read_ctx)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-governed-agent",
                "run_id": run_b_id,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cid}),
                "classification": read_ctx.data_classification,
                "decision": "allow" if read_allow else "deny",
                "reason": read_reason,
            },
            ledger_path,
        )
        if read_allow:
            try:
                tools.read_customer(cid)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị injection yêu cầu gửi dữ liệu ra ngoài (egress)
    if injected is not None:
        egress_ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        egress_allow, egress_reason = policy.check(egress_ctx)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-governed-agent",
                "run_id": run_b_id,
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url}),
                "classification": egress_ctx.data_classification,
                "decision": "allow" if egress_allow else "deny",
                "reason": egress_reason,
            },
            ledger_path,
        )
        if egress_allow:
            # Policy sẽ chặn restricted egress -> không bao giờ chạy vào đây
            tools.http_post(injected.target_url, {"records": []})

    return llm.summarize(docs)
