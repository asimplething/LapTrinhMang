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

    # Tìm kiếm pattern cho Tình trạng (hỗ trợ cả markdown và không markdown)
    status_pattern = r'\*?\*?Tình trạng:\*?\*?\s*(.+?)\s*\n'
    status_match = re.search(status_pattern, text, re.IGNORECASE)
    if status_match:
        status = status_match.group(1).strip()
        if status not in STATUS_WEIGHTS:
            status = "null"

    # Tìm kiếm pattern cho Đánh giá (hỗ trợ cả markdown và không markdown)
    review_pattern = r'\*?\*?Đánh giá:\*?\*?\s*(.+?)(?=\n\S+:|$|\Z)'
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
    # Ưu tiên model theo thứ tự đã định
    for model in MODEL_PRIORITY:
        for candidate in status_details:
            if candidate["model"] == model and candidate["status"] != "null":
                return {
                    "final_status": candidate["status"],
                    "final_review": candidate["review"],
                    "details": status_details
                }

    return {
        "final_status": "null",
        "final_review": "Không thể xác định từ các phản hồi AI",
        "details": status_details
    }
