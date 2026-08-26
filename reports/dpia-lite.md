# Báo cáo Đánh giá Tác động Xử lý Dữ liệu Cá nhân (DPIA-lite)

**Hệ thống**: Customer Support AI Agent (Lab 24 — Governed Agent)  
**Tiêu chuẩn áp dụng**: Nghị định 13/2023/NĐ-CP, Nghị định 356/2025/NĐ-CP, Luật 91/2025/QH15, ISO/IEC 42001

---

## 1. Dữ liệu gì (Data Inventory & Classification)

Hệ thống AI Agent tiếp xúc và xử lý các nhóm dữ liệu cá nhân (PII) sau đây:

| Tool / Luồng dữ liệu | Các trường dữ liệu tiếp cận | Phân loại dữ liệu (Classification) | Nhạy cảm theo NĐ 13/2023 |
|---|---|---|---|
| `tools.search_docs` | Nội dung ticket hỗ trợ, ghi chú khiếu nại, mã ticket ID (`ticket-XXX.md`) | **Internal** (hoặc Public nếu là FAQ) | Không |
| `tools.read_customer` | Họ và tên (`name`), Số Căn cước công dân (`cccd`), Số điện thoại (`phone`), Số tài khoản ngân hàng (`bank_account`), Địa chỉ Email (`email`), Danh sách ticket liên quan (`related_tickets`) | **Restricted** (Dữ liệu cá nhân cơ bản & nhạy cảm) | **Có** (Dữ liệu tài chính STK, định danh CCCD) |
| `agent.pii` (Pre-ingestion Gate) | Quét và phát hiện các mẫu: `VN_CCCD` (12 số), `VN_PHONE` (10 số), `VN_BANK_ACCOUNT` (8-19 số), `EMAIL` | **Sanitization Layer** | Thực hiện che giấu (`[REDACTED_<TYPE>]`) |

---

## 2. Mục đích gì (Purpose of Processing)

- **Mục đích nghiệp vụ hợp pháp**:
  - Tra cứu, tổng hợp và tóm tắt trạng thái các ticket chăm sóc khách hàng đang mở trong tuần để hỗ trợ nhân viên vận hành giải quyết khiếu nại nhanh chóng.
  - Đối soát thông tin khách hàng liên quan trực tiếp đến các ticket được mở hợp lệ (`related_tickets`) nhằm phục vụ quy trình xác minh danh tính và hỗ trợ kỹ thuật.
- **Nguyên tắc giảm thiểu dữ liệu (Data Minimization)**:
  - Agent chỉ trích xuất các mã định danh cần thiết (`ticket_id`) từ tên tệp tin để tra cứu khách hàng hợp lệ, không nạp toàn bộ văn bản tự do của người dùng vào tiến trình xử lý dữ liệu cá nhân nhạy cảm (Run B).

---

## 3. Chảy đi đâu (Data Flows & Cross-Border Transfer Assessment)

### 3.1. Luồng dữ liệu nội bộ (Internal Data Flows)
1. **Context & Bộ nhớ tạm thời**:
   - Run A nạp dữ liệu ticket từ thư mục `corpus/`, trích xuất số ticket hợp lệ (`ticket_id`). Dữ liệu văn bản thô bị cô lập tại Run A và không được chuyển giao sang Run B.
2. **Audit Ledger nội bộ**:
   - Mọi thao tác truy xuất dữ liệu (`search_docs`, `read_customer`, `http_post`) đều được ghi nhận vào `reports/ledger.jsonl` dưới dạng băm bảo mật (`args_hash`, `prev_hash`, `hash`), không lưu trữ lộ PII thô trong nhật ký kiểm toán.
3. **Exfiltration Sink (Môi trường Lab)**:
   - Cổng ra `http_post` chỉ trỏ tới `localhost:9999`. Chính sách bảo mật tại PEP (`agent/policy.py`) đã chặn hoàn toàn việc gửi dữ liệu `restricted` ra ngoài qua mạng (`decision=deny`).

### 3.2. Đánh giá Chuyển Dữ liệu Xuyên Biên giới (NĐ 356/2025/NĐ-CP)
- **Kịch bản `--mock` (Mặc định trong môi trường Gov)**:
  - 100% dữ liệu được xử lý on-premises/local, không có bất kỳ lệnh gọi API nào ra máy chủ nước ngoài. Đảm bảo tuân thủ tuyệt đối về chủ quyền dữ liệu.
- **Kịch bản tích hợp LLM nước ngoài (ví dụ Anthropic Claude qua `--model`)**:
  - **Bản chất**: Việc gửi nội dung ticket hoặc thông tin định danh khách hàng tới API endpoint của nhà cung cấp LLM đặt tại nước ngoài cấu thành hành vi **chuyển dữ liệu cá nhân xuyên biên giới** theo quy định tại Điều 43 NĐ 13/2023 và NĐ 356/2025.
  - **Biện pháp kiểm soát áp dụng**:
    1. **PII Redaction Gate**: Văn bản trước khi gửi qua API phải được lọc và ẩn danh hóa thông qua `agent.pii.redact()`.
    2. **Egress Control**: Chặn mọi kênh gửi dữ liệu ra ngoài khi context chứa dữ liệu phân loại `restricted`.
    3. **Hồ sơ Đánh giá Tác động**: Doanh nghiệp cần lập và gửi Hồ sơ đánh giá tác động chuyển dữ liệu ra nước ngoài tới Cục An ninh mạng và phòng, chống tội phạm sử dụng công nghệ cao (A05) trong vòng 60 ngày kể từ ngày bắt đầu xử lý.
