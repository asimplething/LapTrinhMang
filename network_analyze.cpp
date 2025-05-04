#include <iostream>
#include <cstdlib> // Để sử dụng hàm system()
#include <string>

#ifdef _WIN32
#include <windows.h> // Để sử dụng SetConsoleOutputCP và Sleep
#else
#include <unistd.h>  // Để sử dụng sleep trên Linux/MacOS
#endif

int main()
{
#ifdef _WIN32
    // Thiết lập console output sang UTF-8 trên Windows
    SetConsoleOutputCP(CP_UTF8);
    std::wcout.imbue(std::locale(""));
#endif

    // Đường dẫn và lệnh chạy các script
    const char *capture_script = "python3 wifi_capture.py";
    const char *ai_agent_script = "python3 AI_agent.py";
    const char *viewer_script = "python3 web_viewer.py";

    int sleep_time = 5; // Thời gian chờ giữa các lần chạy (giây)
    bool viewer_started = false;

    while (true)
    {
        // Chạy web.viewer.py một lần duy nhất
        if (!viewer_started)
        {
            std::cout << "[INFO] Đang khởi chạy web.viewer.py...\n";
#ifdef _WIN32
            // Windows: mở tab mới chạy nền
            system(("start " + std::string(viewer_script)).c_str());
#else
            // Linux/MacOS: chạy ngầm với dấu &
            system((std::string(viewer_script) + " &").c_str());
#endif
            viewer_started = true;
        }

        // Chạy script bắt gói tin
        std::cout << "---------------------------------------------------------" << std::endl;
        int capture_result = system(capture_script);
        if (capture_result != 0)
        {
            std::cerr << "[ERROR] wifi_capture.py gặp lỗi, thử lại sau vài giây...\n";
#ifdef _WIN32
            Sleep(sleep_time * 1000);
#else
            sleep(sleep_time);
#endif
            continue;
        }

        // Chạy script AI agent
        int ai_result = system(ai_agent_script);

#ifdef _WIN32
        Sleep(sleep_time * 1000);
#else
        sleep(sleep_time);
#endif
        std::cout << "\n" << std::endl;
    }

    return 0;
}
