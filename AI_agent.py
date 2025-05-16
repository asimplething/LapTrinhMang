import os
import sys
import json
from scapy.all import rdpcap
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient

# Tool cho AI agent để bắt gói tin và phân tích
from tools.network_capture_tool import network_capture_tool
from tools.pcap_extract_tool import pcap_extract_tool
from tools.log_tool import write_log_tool, read_log_tool
from autogen_core.tools import FunctionTool

# Template cho các system message
from system_message_template.message_template import analyze_template, writer_template
import datetime
from dotenv import load_dotenv
from network_evaluation import evaluate_results, STATUS_WEIGHTS
from collections import defaultdict
import asyncio
from write_log import write_log_agents, write_log_conclusion
import time

sys.stdout.reconfigure(encoding='utf-8')
print("Đang chạy AI agent...")

# Nhận tham số từ command-line
if len(sys.argv) < 7:
    raise ValueError("Thiếu tham số: minimum_network_limit, maximum_network_limit và output_capture_file")
minimum_network_limit = sys.argv[1]
maximum_network_limit = sys.argv[2]
output_capture_file = sys.argv[3]
capture_interface = sys.argv[4]
capture_duration = int(sys.argv[5])
maximum_packets_capture = int(sys.argv[6])

# Đường dẫn tới file PCAPNG
file_path = output_capture_file
json_file_path = "content/extracted_data.json"

# Số lương gói tin tối đa mỗi phần gửi cho AI agent
chunk_size = 100

print("Đang tải API KEY...")
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("API_KEY not found in environment variables.")

# Custom input function to return one chunk at a time
async def run_AIagent(assistant_gemini, assistant_deepseek, assistant_qwen, data_chunks_list):
    current_chunk_index = 0
    results = []

    print("Đang phân tích tệp tin PCAPNG...")
    if not isinstance(data_chunks_list, list):
        print(f"Error: Expected data_chunks_list to be a list, but got {type(data_chunks_list)}")     
        return results

    while current_chunk_index < len(data_chunks_list):
        chunk = data_chunks_list[current_chunk_index]
        message = f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks_list)}:" \
                  f"\n - Chi tiết: \n{json.dumps(chunk, indent=4, ensure_ascii=False)}"

        gemini_result, deepseek_result, qwen_result = await run_models_parallel(assistant_gemini, assistant_deepseek, assistant_qwen, message)

        results = write_log_agents(gemini_result, deepseek_result, qwen_result, current_chunk_index, data_chunks_list, results)
        current_chunk_index += 1
    return results

# Chạy song song các model phân tích gói tin
async def run_models_parallel(assistant_gemini, assistant_deepseek, assistant_qwen, chunk):
    gemini_task = assistant_gemini.run(task=chunk)
    deepseek_task = assistant_deepseek.run(task=chunk)
    qwen_task = assistant_qwen.run(task=chunk)

    result = await asyncio.gather(gemini_task, deepseek_task, qwen_task)
    return result

async def run_AIagent_capture_packets():
    data = await capture_agent.run(task=f"hãy bắt gói tin và chiết xuất thông tin tệp pcap bằng 2 tool (sử dụng cả 2 tool tôi cung cấp cho bạn) từ interface là {capture_interface} với output là {output_capture_file}, max packets là {maximum_packets_capture}, duration là {capture_duration}, chunk_size là {chunk_size}")
    return data
 #Sau khi có results từ asyncio.run(), thêm phần phân tích:
def analyze_final_results(results):
    print("Đang phân tích kết quả cuối cùng...")
    # Chia results thành các nhóm 3 (gemini, deepseek, qwen)
    grouped_results = [results[i:i+3] for i in range(0, len(results), 3)]
    final_evaluations = []
    evaluations_data = []

    # Mở file log tổng hợp để ghi kết quả đánh giá
    log_file = os.path.join("log", "network_analysis_log.txt")

    with open(log_file, "a", encoding="utf-8") as f:

        for idx, group in enumerate(grouped_results):
            evaluation = evaluate_results(group)
            final_evaluations.append(evaluation)
            
            # Lưu thông tin đánh giá để chuẩn bị cho báo cáo tổng hợp
            part_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            evaluation_data = {
                "part": idx+1,
                "total_parts": len(grouped_results),
                "timestamp": part_timestamp,
                "status": evaluation['final_status'],
                "review": evaluation['final_review'],
                "details": evaluation['details']
            }
            evaluations_data.append(evaluation_data)
            
    return final_evaluations, evaluations_data

# Cấu hình model AI
gemini_model = OpenAIChatCompletionClient(
    model="gemini-1.5-flash",
    api_key=GEMINI_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    }
)

deepseek_model = OpenAIChatCompletionClient(
    #model="gemini-2.0-flash",
    #api_key=GEMINI_API_KEY,
    model="deepseek-chat",
    base_url="https://api.deepseek.com",
    api_key=DEEPSEEK_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    },
)

llama_model = OpenAIChatCompletionClient(
    #model="meta-llama/llama-3.3-8b-instruct:free",
    #base_url="https://openrouter.ai/api/v1",
    #api_key=OPENROUTER_API_KEY,
    model="gemini-2.0-flash",
    api_key=GEMINI_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    },
)


# Thiết lập agent bắt gói tin và chiết xuất thông tin
capture_agent = AssistantAgent(
    name="CaptureAgent",
    model_client=gemini_model,
    #system_message=system_message_network_capture_template,
    tools=[FunctionTool(network_capture_tool, description="Tool to capture network packets", strict=True),
               FunctionTool(pcap_extract_tool, description="Tool to extract information from pcap file", strict=True)],
)

# Thiết lập agent phân tích
assistant_gemini = AssistantAgent(
    name="Assistant",
    model_client=gemini_model,
    system_message=analyze_template(maximum_network_limit, minimum_network_limit),
)

assistant_deepseek = AssistantAgent(
    name="Assistant",
    model_client=deepseek_model, # Corrected
    system_message=analyze_template(maximum_network_limit, minimum_network_limit),
)

assistant_qwen = AssistantAgent(
    name="Assistant",
    model_client=llama_model,
    system_message=analyze_template(maximum_network_limit, minimum_network_limit),
)

assistant_writer = AssistantAgent(
    name="Assistant",
    model_client=deepseek_model,
    system_message=writer_template(),
)

data_chunks_from_tool = None # Renamed from data_chunks to avoid confusion before parsing
is_network_captured = False

# Bắt gói tin và chiết xuất thông tin từ tệp PCAPNG
while True:
    results_capture_extract = asyncio.run(run_AIagent_capture_packets()) # Renamed 'results'
    # Tìm ToolCallExecutionEvent
    for message in results_capture_extract.messages:
        if message.type == 'ToolCallExecutionEvent':
            for tool_result in message.content:
                print(tool_result.name)
                if tool_result.name == 'network_capture_tool' and not tool_result.is_error: # Removed 'is_network_captured is False' here as it's set below
                    # We should check tool_result.content['success'] if possible,
                    # but for now, just being called without error is the trigger.
                    print(f"network_capture_tool output: {tool_result.content}")
                    # Attempt to interpret the tool_result.content to set is_network_captured
                    capture_successful = False
                    if isinstance(tool_result.content, dict) and tool_result.content.get("success") is True:
                        capture_successful = True
                    elif isinstance(tool_result.content, str): # If content is a string, try to parse as JSON
                        try:
                            parsed_content = json.loads(tool_result.content)
                            if isinstance(parsed_content, dict) and parsed_content.get("success") is True:
                                 capture_successful = True
                            else:
                                print("network_capture_tool output was parsable JSON but did not indicate success.")
                        except json.JSONDecodeError:
                            print("network_capture_tool output was a string but not valid JSON.")
                    else:
                        print(f"network_capture_tool output was not in expected format (dict or JSON string). Type: {type(tool_result.content)}")

                    if capture_successful:
                        is_network_captured = True
                        print("Network capture reported success.")
                    else:
                        print("Network capture did NOT report success.")
                        is_network_captured = False # Explicitly set to false if not successful

                if tool_result.name == 'pcap_extract_tool' and not tool_result.is_error and is_network_captured is True:
                    print(f"pcap_extract_tool output: {tool_result.content}")
                    data_chunks_from_tool = tool_result.content

    if data_chunks_from_tool is None or is_network_captured is False:
        print(f"AI không bắt được gói tin thành công hoặc không chiết xuất được thông tin. Capture success status: {is_network_captured}, Extracted data: {data_chunks_from_tool}")
        # C++ wrapper handles retry and sleep, so Python script should exit to signal failure for this attempt.
        print("Exiting AI_agent.py to allow the main program to retry.")
        sys.exit(1)
    else:
        print("Successfully captured and extracted data. Proceeding to analysis.")
        break

# Initialize data_chunks_parsed to a default value (e.g., None or an empty list)
# to ensure it's defined in case of early exit.
data_chunks_parsed = None

if data_chunks_from_tool is None: # This check is somewhat redundant given the loop exit condition but kept for safety
    print(f"Error: data_chunks_from_tool is None after capture loop. Cannot proceed.")
    print("This implies an issue with the capture/extraction logic or tool responses.")
    print("Exiting AI_agent.py.")
    sys.exit(1)

elif isinstance(data_chunks_from_tool, str):
    if data_chunks_from_tool.strip().lower() == "none":
        print(f"Error: data_chunks_from_tool is the literal string 'None'. Cannot parse JSON.")
        print("This indicates pcap_extract_tool likely failed or returned None, which was then stringified by the framework.")
        print("Check logs for pcap_extract_tool and network_capture_tool for more details.")
        print("Exiting AI_agent.py.")
        sys.exit(1)
    elif not data_chunks_from_tool.strip():
        print(f"Error: data_chunks_from_tool is an empty or whitespace-only string: '{data_chunks_from_tool}'. Cannot parse JSON.")
        print("pcap_extract_tool might have returned an empty string unexpectedly.")
        print("Exiting AI_agent.py.")
        sys.exit(1)

    try:
        data_chunks_parsed = json.loads(data_chunks_from_tool)
        print(f"Successfully parsed JSON string from pcap_extract_tool.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from data_chunks_from_tool string: {e}")
        print(f"Content of data_chunks_from_tool string that failed to parse: >>>{data_chunks_from_tool}<<<")
        print("This could be due to malformed JSON output from pcap_extract_tool.")
        print("Exiting AI_agent.py.")
        sys.exit(1)
elif isinstance(data_chunks_from_tool, (list, dict)):
    print("data_chunks_from_tool is already a Python object (list/dict). Assuming it's the parsed data.")
    data_chunks_parsed = data_chunks_from_tool
else:
    print(f"Error: data_chunks_from_tool is of an unexpected type: {type(data_chunks_from_tool)}. Content: {data_chunks_from_tool}")
    print("Expected a JSON string, or a list/dict if already parsed by the framework.")
    print("Exiting AI_agent.py.")
    sys.exit(1)

if data_chunks_parsed is None:
    print("Critical Error: data_chunks_parsed is None after all processing attempts.")
    print(f"Original data_chunks_from_tool content was: >>>{data_chunks_from_tool}<<<")
    print("This points to a flaw in the data handling or tool output interpretation logic.")
    print("Exiting AI_agent.py.")
    sys.exit(1)

if not isinstance(data_chunks_parsed, list):
    print(f"Critical Error: data_chunks_parsed is not a list as expected by run_AIagent. Type: {type(data_chunks_parsed)}")
    print(f"Content: {data_chunks_parsed}")
    print("The pcap_extract_tool should return a list of chunks (even if it's a JSON string representing that list).")
    print("Exiting AI_agent.py.")
    sys.exit(1)

analysis_results = asyncio.run(run_AIagent(assistant_gemini, assistant_deepseek, assistant_qwen, data_chunks_parsed))

final_evaluations, evaluations_data = analyze_final_results(analysis_results)

overall_status = defaultdict(int)
for eval_item in final_evaluations:
    overall_status[eval_item["final_status"]] += 1

# Tạo báo cáo tổng hợp bằng assistant_writer
print("Đang tạo báo cáo tổng hợp...")
# Chuẩn bị input cho assistant_writer
evaluations_text = ""
for eval_data in evaluations_data:
    evaluations_text += f"[PHẦN {eval_data['part']}/{eval_data['total_parts']} - {eval_data['timestamp']}]\n"
    evaluations_text += f"**Tình trạng:** {eval_data['status']}\n"
    evaluations_text += f"**Đánh giá:** {eval_data['review']}\n\n"

# Thêm thông tin tổng hợp
summary_text = f"Thống kê trạng thái:\n"
for status, count in overall_status.items():
    summary_text += f"- {status}: {count} phần\n"

# Xác định trạng thái cuối cùng
if overall_status:
    sorted_statuses = sorted(overall_status.keys(),
                          key=lambda x: STATUS_WEIGHTS.get(x, 0),
                          reverse=True)
    if sorted_statuses:
        final_status = sorted_statuses[0]
    else:
        final_status = "Không xác định"
else:
    final_status = "Không xác định"

summary_text += f"\nTrạng thái cuối cùng: {final_status}\n"

# Gửi đến assistant_writer để viết báo cáo
writer_input = f"Dữ liệu phân tích mạng:\n\n{evaluations_text}\n{summary_text}"
report_result = asyncio.run(assistant_writer.run(task=writer_input))

# Ghi kết luận tổng thể
print("Đang ghi kết luận tổng thể vào file log...")
write_log_conclusion(overall_status, report_result.messages)

# Cập nhật timestamp phân tích để web page biết khi nào cần reload
try:
    timestamp_file = os.path.join("log", "analysis_timestamp.txt")
    os.makedirs(os.path.dirname(timestamp_file), exist_ok=True)
    with open(timestamp_file, 'w', encoding='utf-8') as f:
        f.write(str(int(time.time())))
    print("Đã cập nhật timestamp phân tích mới nhất.")
except Exception as e:
    print(f"[ERROR] Lỗi khi cập nhật timestamp phân tích: {e}")
