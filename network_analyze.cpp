#include <iostream>
#include <cstdlib> // Để sử dụng hàm system()
#include <string>
#include <map>
#include <fstream> // Để sử dụng ifstream

#ifdef _WIN32
#include <windows.h> // Để sử dụng SetConsoleOutputCP và Sleep
#else
#include <unistd.h> // Để sử dụng sleep trên Linux/MacOS
#endif

// Các biến toàn cục để lưu các tham số cấu hình
const std::string config_file = "config/system_config.txt";
std::string capture_duration;
std::string maximum_packets_capture;
std::string output_capture_file;
std::string minimum_network_limit;
std::string maximum_network_limit;
std::string capture_interface;
std::map<std::string, std::string> config;

// Hàm để đọc file cấu hình và trả về map các tham số
std::map<std::string, std::string> read_config_file(const std::string &config_file)
{
    std::ifstream file(config_file);
    if (!file.is_open())
    {
        std::cerr << "Lỗi: Không thể mở file cấu hình: " << config_file << std::endl;
        exit(1);
    }

    std::string line;
    while (std::getline(file, line))
    {
        // Bỏ qua dòng trống và comment
        if (line.empty() || line[0] == '#')
            continue;

        // Tách key và value
        size_t pos = line.find('=');
        if (pos != std::string::npos)
        {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            // Loại bỏ dấu ngoặc kép nếu có
            if (value.front() == '"' && value.back() == '"')
            {
                value = value.substr(1, value.size() - 2);
            }
            config[key] = value;
            std::cout << "[INFO] Đã đọc tham số: " << key << " = " << value << std::endl;
        }
    }
    file.close();
    return config;
}

int loadConfigFile()
{
    std::cout << "[INFO] Đang kiểm tra lại cấu hình...\n";
    // Đường dẫn đến file cấu hình
   

    // Đọc file cấu hình
    std::map<std::string, std::string> config = read_config_file(config_file);

    // Kiểm tra xem tất cả các tham số cần thiết có trong config không
    if (config.find("capture_interface") == config.end() ||
        config.find("capture_duration") == config.end() ||
        config.find("maximum_packets_capture") == config.end() ||
        config.find("output_capture_file") == config.end() ||
        config.find("minimum_network_limit") == config.end() ||
        config.find("maximum_network_limit") == config.end())

    {
        std::cerr << "[ERROR] Một hoặc nhiều tham số chưa được thiết lập trong file cấu hình." << std::endl;
        return 1;
    }
    return 0;
}

int main()
{
#ifdef _WIN32
    // Thiết lập console output sang UTF-8 trên Windows
    SetConsoleOutputCP(CP_UTF8);
    std::wcout.imbue(std::locale(""));
#endif
    std::cout << "Đây là màn hình debug của chương trình phân tích mạng.\nThầy có thể xem trạng thái mạng ở giao diện web: http://localhost:5000\n";
    std::cout << "[INFO] Bắt đầu chương trình phân tích mạng...\n";
    int sleep_time = 5; // Thời gian chờ giữa các lần chạy (giây)
    bool viewer_started = false;

    while (true)
    {
        std::cout << "---------------------------------------------------------" << std::endl;
        // Đọc lại file cấu hình mỗi lần lặp
        if(loadConfigFile() != 0)
        {
            std::cerr << "[ERROR] Không thể tải file cấu hình, thoát chương trình.\n";
            return 1;
        }
        
        // Lấy các giá trị từ config
        capture_duration = config["capture_duration"];
        maximum_packets_capture = config["maximum_packets_capture"];
        output_capture_file = config["output_capture_file"];
        minimum_network_limit = config["minimum_network_limit"];
        maximum_network_limit = config["maximum_network_limit"];
        capture_interface = config["capture_interface"];

        // Đường dẫn và lệnh chạy các script
        std::string capture_script = "python3 network_capture.py " + capture_duration + " " +
                                     maximum_packets_capture + " " + output_capture_file + " " +
                                     capture_interface;
        std::cout << "[INFO] Đang chạy script bắt gói tin: " << capture_script << std::endl;
        std::string ai_agent_script = "python3 AI_agent.py \"" + minimum_network_limit + "\" \"" +
                                      maximum_network_limit + "\" " + output_capture_file;
        std::cout << "[INFO] Đang chạy script AI agent: " << ai_agent_script << std::endl;
        std::string viewer_script = "python3 web_viewer.py";
        std::cout << "[INFO] Đang chạy script web viewer: " << viewer_script << std::endl;

        // Chạy web.viewer.py một lần duy nhất
        if (!viewer_started)
        {
            std::cout << "[INFO] Đang khởi chạy web.viewer.py...\n";
#ifdef _WIN32
            // Windows: mở tab mới chạy nền
            system(("start " + viewer_script).c_str());
#else
            // Linux/MacOS: chạy ngầm với dấu &
            system((viewer_script + " &").c_str());
#endif
            viewer_started = true;
        }

        // Chạy script bắt gói tin
        int capture_result = system(capture_script.c_str());
        if (capture_result != 0)
        {
            std::cerr << "[ERROR] network_capture.py gặp lỗi, thử lại sau vài giây...\n";
#ifdef _WIN32
            Sleep(sleep_time * 1000);
#else
            sleep(sleep_time);
#endif
            continue;
        }

        // Chạy script AI agent
        int ai_result = system(ai_agent_script.c_str());
        if (ai_result != 0)
        {
            std::cerr << "[ERROR] AI_agent.py gặp lỗi, thử bắt gói tin và phân tích lại...\n";
#ifdef _WIN32
            Sleep(sleep_time * 1000);
#else
            sleep(sleep_time);
#endif
            std::cout << "\n"
                      << std::endl;
        }
    }
    return 0;
}