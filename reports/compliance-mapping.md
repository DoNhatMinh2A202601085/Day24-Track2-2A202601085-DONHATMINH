# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Cơ chế cascade deletion cho dữ liệu cá nhân của chủ thể | (Chưa implement, xem stretch goal #3) |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call & kiểm soát luồng dữ liệu xuyên biên giới | `reports/dpia-lite.md` §2, §3 |
| ASI03 — privilege abuse | Phân quyền theo ngữ cảnh (PEP), per-agent/run identity (`agent_owner`, `run_id`, `delegation_depth`) + Audit Ledger ghi nhận mọi tool call | `agent/policy.py:L14-L45`, `agent/runner.py:L31-L125`, `agent/ledger.py:L8-L36` |
| ASI01 — goal hijack | Trifecta split: cô lập Run A (untrusted content) và Run B (private data qua `related_tickets`), chặn egress cho dữ liệu restricted | `agent/runner.py:L31-L125`, `reports/attack-after.log`, `tests/test_split.py:L75-L117` |
| ISO 42001 Clause 5-6 | Quản trị chính sách an toàn AI (Policy-as-code), kiểm soát phiên bản và thẩm định quy trình | `agent/policy.py:L30-L45`, git commit log của `agent/policy.py` |
