#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <sddl.h>

// Define _WIN32_WINNT for Windows Vista or later to ensure WTS APIs are available
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

// Fallback definition for WTSSessionName in case it's undefined
#ifndef WTSSessionName
#define WTSSessionName 5
#endif

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

std::string getProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "Unknown";
    char processName[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (GetProcessImageFileNameA(hProcess, processName, size) > 0) {
        std::string fullPath(processName);
        size_t lastSlash = fullPath.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            CloseHandle(hProcess);
            return fullPath.substr(lastSlash + 1);
        }
        CloseHandle(hProcess);
        return fullPath;
    }
    CloseHandle(hProcess);
    return "Unknown";
}

std::string getProcessOwner(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "Unknown";

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return "Unknown";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return "Unknown";
    }

    std::string owner = "Unknown";
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        char name[256], domain[256];
        DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
        SID_NAME_USE sidType;
        if (LookupAccountSidA(NULL, pTokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
            owner = std::string(domain) + "\\" + std::string(name);
        }
    }

    free(pTokenUser);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return owner;
}

std::string getSessionName(DWORD sessionId) {
    WCHAR* sessionName = nullptr;
    DWORD bytesReturned = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, (WTS_INFO_CLASS)WTSSessionName, &sessionName, &bytesReturned)) {
        std::wstring ws(sessionName);
        WTSFreeMemory(sessionName);
        return std::string(ws.begin(), ws.end());
    }
    return "Unknown";
}

std::string getMemoryUsage(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "Unknown";

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        CloseHandle(hProcess);
        return std::to_string(pmc.WorkingSetSize / 1024) + " K";
    }
    CloseHandle(hProcess);
    return "Unknown";
}

std::string getProcessStatus(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "Unknown";
    CloseHandle(hProcess);
    return "Running"; // Simplified: assume accessible processes are running
}

std::string getCPUTime(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "Unknown";

    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER kTime, uTime;
        kTime.LowPart = kernelTime.dwLowDateTime;
        kTime.HighPart = kernelTime.dwHighDateTime;
        uTime.LowPart = userTime.dwLowDateTime;
        uTime.HighPart = userTime.dwHighDateTime;

        ULONGLONG totalTime = (kTime.QuadPart + uTime.QuadPart) / 10000000;
        DWORD hours = static_cast<DWORD>(totalTime / 3600);
        DWORD minutes = static_cast<DWORD>((totalTime % 3600) / 60);
        DWORD seconds = static_cast<DWORD>(totalTime % 60);
        char buffer[16];
        snprintf(buffer, sizeof(buffer), "%u:%02u:%02u", hours, minutes, seconds);
        CloseHandle(hProcess);
        return std::string(buffer);
    }
    CloseHandle(hProcess);
    return "Unknown";
}

struct EnumWindowsData {
    DWORD pid;
    std::string title;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumWindowsData* data = reinterpret_cast<EnumWindowsData*>(lParam);
    DWORD windowPid;
    GetWindowThreadProcessId(hwnd, &windowPid);
    if (windowPid == data->pid && IsWindowVisible(hwnd)) {
        char title[256];
        if (GetWindowTextA(hwnd, title, sizeof(title)) > 0) {
            data->title = title;
            return FALSE; // Stop enumeration once we find a visible window
        }
    }
    return TRUE;
}

std::string getWindowTitle(DWORD pid) {
    EnumWindowsData data = { pid, "N/A" };
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));
    return data.title;
}

void printTableHeader() {
    std::cout << "\n";
    std::cout << "+" << std::string(25, '-') << "+" << std::string(10, '-') << "+"
        << std::string(17, '-') << "+" << std::string(12, '-') << "+"
        << std::string(13, '-') << "+" << std::string(15, '-') << "+"
        << std::string(50, '-') << "+" << std::string(13, '-') << "+"
        << std::string(30, '-') << "+\n";
    std::cout << "|" << std::setw(25) << std::left << " Image Name"
        << "|" << std::setw(10) << std::right << " PID"
        << "|" << std::setw(17) << std::left << " Session Name"
        << "|" << std::setw(12) << std::right << " Session#"
        << "|" << std::setw(13) << std::right << " Mem Usage"
        << "|" << std::setw(15) << std::left << " Status"
        << "|" << std::setw(50) << std::left << " User Name"
        << "|" << std::setw(13) << std::left << " CPU Time"
        << "|" << std::setw(30) << std::left << " Window Title" << "|\n";
    std::cout << "+" << std::string(25, '-') << "+" << std::string(10, '-') << "+"
        << std::string(17, '-') << "+" << std::string(12, '-') << "+"
        << std::string(13, '-') << "+" << std::string(15, '-') << "+"
        << std::string(50, '-') << "+" << std::string(13, '-') << "+"
        << std::string(30, '-') << "+\n";
}

void printTableFooter() {
    std::cout << "+" << std::string(25, '-') << "+" << std::string(10, '-') << "+"
        << std::string(17, '-') << "+" << std::string(12, '-') << "+"
        << std::string(13, '-') << "+" << std::string(15, '-') << "+"
        << std::string(50, '-') << "+" << std::string(13, '-') << "+"
        << std::string(30, '-') << "+\n";
}

int main() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot\n";
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    printTableHeader();

    if (Process32First(hSnapshot, &pe32)) {
        do {
            DWORD sessionId = 0;
            ProcessIdToSessionId(pe32.th32ProcessID, &sessionId);
            std::string sessionName = getSessionName(sessionId);
            std::string processName = getProcessName(pe32.th32ProcessID);
            std::string owner = getProcessOwner(pe32.th32ProcessID);
            std::string memUsage = getMemoryUsage(pe32.th32ProcessID);
            std::string status = getProcessStatus(pe32.th32ProcessID);
            std::string cpuTime = getCPUTime(pe32.th32ProcessID);
            std::string windowTitle = getWindowTitle(pe32.th32ProcessID);

            std::cout << "|" << std::setw(25) << std::left << processName
                << "|" << std::setw(10) << std::right << pe32.th32ProcessID
                << "|" << std::setw(17) << std::left << sessionName
                << "|" << std::setw(12) << std::right << sessionId
                << "|" << std::setw(13) << std::right << memUsage
                << "|" << std::setw(15) << std::left << status
                << "|" << std::setw(50) << std::left << owner
                << "|" << std::setw(13) << std::left << cpuTime
                << "|" << std::setw(30) << std::left << windowTitle << "|\n";
        } while (Process32Next(hSnapshot, &pe32));
    }

    printTableFooter();
    CloseHandle(hSnapshot);
    return 0;
}