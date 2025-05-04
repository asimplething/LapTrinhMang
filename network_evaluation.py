import re
from collections import defaultdict
from typing import Dict, List, Tuple

# Định nghĩa trọng số và thứ tự ưu tiên
STATUS_WEIGHTS = {
    "Mạng sập": 5,
    "Bị tấn công": 4,
    "Nghẽn mạng": 3,
    "Đáng ngờ": 2,
    "Tốt": 1,
    "null": 0
}

MODEL_PRIORITY = ["gemini", "deepseek", "qwen"]

def extract_status_review(text: str) -> Tuple[str, str]:
    #Trích xuất trạng thái và đánh giá từ nội dung text
    status = None
    review = None

    # Tìm kiếm pattern cho Tình trạng
    status_pattern = r'Tình trạng:\s*(.+?)\s*\n'
    status_match = re.search(status_pattern, text, re.IGNORECASE)
    if status_match:
        status = status_match.group(1).strip()
        if status not in STATUS_WEIGHTS:
            status = "null"

    # Tìm kiếm pattern cho Đánh giá
    review_pattern = r'Đánh giá:\s*(.+?)(?=\n\S+:|$|\Z)'
    review_match = re.search(review_pattern, text, re.IGNORECASE | re.DOTALL)
    if review_match:
        review = review_match.group(1).strip()

    return status or "null", review or "Không có đánh giá"

def evaluate_results(results: List[str]) -> Dict:
    ###
    #Đánh giá và tổng hợp kết quả từ nhiều model
    #Args:
    #    results: Danh sách các kết quả từ model (theo thứ tự gemini, deepseek, qwen)
    #Returns:
    #    Dict: Kết quả tổng hợp gồm final_status, final_review và details
    ###

    status_count = defaultdict(int)
    status_details = []
    model_names = ["gemini", "deepseek", "qwen"]

    for idx, content in enumerate(results):
        model_name = model_names[idx % len(model_names)]
        status, review = extract_status_review(content)

        status_count[status] += 1
        status_details.append({
            "model": model_name,
            "status": status,
            "review": review,
            "weight": STATUS_WEIGHTS[status]
        })

    # Lọc các status hợp lệ (loại trừ null)
    valid_statuses = [s for s in status_count if s != "null"]

    # Trường hợp tất cả đều null
    if not valid_statuses:
        return {
            "final_status": "null",
            "final_review": "Không thể xác định từ các phản hồi AI",
            "details": status_details
        }

    # Kiểm tra đa số 2/3
    for status, count in status_count.items():
        if count >= 2 and status != "null":
            selected_status = status
            # Tìm đánh giá đầu tiên từ model có status trùng khớp
            selected_review = next(
                (d["review"] for d in status_details if d["status"] == selected_status),
                status_details[0]["review"]
            )
            return {
                "final_status": selected_status,
                "final_review": selected_review,
                "details": status_details
            }

    # Trường hợp không có đa số - chọn trọng số cao nhất
    max_weight = -1
    candidates = []

    for detail in status_details:
        if detail["status"] == "null":
            continue
        if detail["weight"] > max_weight:
            max_weight = detail["weight"]
            candidates = [detail]
        elif detail["weight"] == max_weight:
            candidates.append(detail)

    if not candidates:
        return {
            "final_status": "null",
            "final_review": "Không thể xác định từ các phản hồi AI",
            "details": status_details
        }

    # Ưu tiên model theo thứ tự đã định
    for model in MODEL_PRIORITY:
        for candidate in candidates:
            if candidate["model"] == model:
                return {
                    "final_status": candidate["status"],
                    "final_review": candidate["review"],
                    "details": status_details
                }

    # Fallback
    return {
        "final_status": candidates[0]["status"],
        "final_review": candidates[0]["review"],
        "details": status_details
    }

def generate_alert(final_evaluation: Dict) -> str:
    #Tạo thông báo cảnh báo từ kết quả đánh giá
    alert_status = final_evaluation["final_status"]

    if alert_status == "Tốt":
        return "✅ Hệ thống hoạt động bình thường"
    elif alert_status == "null":
        return "⚠️ Không thể xác định trạng thái hệ thống"

    # Tạo thông báo cảnh báo chi tiết
    alert_msg = [
        f"🚨 CẢNH BÁO: {alert_status}",
        f"Lý do: {final_evaluation['final_review']}"
    ]

    return "\n".join(alert_msg)
