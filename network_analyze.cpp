#include <iostream>
#include <cstdlib> // Để sử dụng hàm system()
#include <string>

#ifdef _WIN32
#include <windows.h> // Để sử dụng SetConsoleOutputCP và Sleep
#else
#include <unistd.h> // Để sử dụng sleep trên Linux/MacOS
#endif

int main()
{
#ifdef _WIN32
    // Thiết lập console output sang UTF-8 trên Windows
    SetConsoleOutputCP(CP_UTF8);
    // Đảm bảo std::wcout được sử dụng cho tiếng Việt
    std::wcout.imbue(std::locale(""));
#endif

    // Đường dẫn và lệnh chạy hai script Python
    const char *capture_script = "python3 wifi_capture.py";
    const char *ai_agent_script = "python3 AI_agent.py";
    int sleep_time = 5; // Thời gian chờ giữa các lần chạy (giây)

    while (true)
    {
        // Chạy script bắt gói tin
        std::cout << "---------------------------------------------------------" << std::endl;
        int capture_result = system(capture_script);
        if (capture_result != 0)
        {
#ifdef _WIN32
            Sleep(sleep_time * 1000); // Windows: Sleep tính bằng ms
#else
            sleep(sleep_time); // Linux/MacOS: sleep tính bằng giây
#endif
            continue; // Nếu lỗi, chờ và thử lại vòng lặp
        }
        // Chạy script AI agent
        int ai_result = system(ai_agent_script);
#ifdef _WIN32
        Sleep(sleep_time * 1000); // Windows: Sleep tính bằng ms
#else
        sleep(sleep_time); // Linux/MacOS: sleep tính bằng giây
#endif
        std::cout << "\n"
                  << std::endl;
    }

    return 0;
}