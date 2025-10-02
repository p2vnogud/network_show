#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <windows.h>
#include <psapi.h>
#include <sddl.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

std::string ipToString(const void* addr, int family) {
    char buf[INET6_ADDRSTRLEN] = { 0 };
    if (family == AF_INET) {
        struct in_addr inAddr;
        memcpy(&inAddr, addr, sizeof(inAddr));
        inet_ntop(AF_INET, &inAddr, buf, sizeof(buf));
    }
    else if (family == AF_INET6) {
        struct in6_addr in6Addr;
        memcpy(&in6Addr, addr, sizeof(in6Addr));
        inet_ntop(AF_INET6, &in6Addr, buf, sizeof(buf));
    }
    return std::string(buf);
}

std::string stateToString(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return "CLOSED";
    case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

std::string getProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return "Unknown";
    }
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
    if (hProcess == NULL) {
        return "Unknown";
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return "Unknown";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (pTokenUser == NULL) {
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

void printTableHeader() {
    std::cout << "\nActive Connections\n\n";
    std::cout << "+" << std::string(8, '-') << "+" << std::string(24, '-') << "+"
        << std::string(24, '-') << "+" << std::string(14, '-') << "+"
        << std::string(8, '-') << "+" << std::string(22, '-') << "+"
        << std::string(30, '-') << "+\n";
    std::cout << "|" << std::setw(8) << std::left << " Proto"
        << "|" << std::setw(24) << std::left << " Local Address"
        << "|" << std::setw(24) << std::left << " Foreign Address"
        << "|" << std::setw(14) << std::left << " State"
        << "|" << std::setw(8) << std::right << " PID"
        << "|" << std::setw(22) << std::left << " Image Name"
        << "|" << std::setw(30) << std::left << " Owner" << "|\n";
    std::cout << "+" << std::string(8, '-') << "+" << std::string(24, '-') << "+"
        << std::string(24, '-') << "+" << std::string(14, '-') << "+"
        << std::string(8, '-') << "+" << std::string(22, '-') << "+"
        << std::string(30, '-') << "+\n";
}

void printTcpTable(int family) {
    DWORD size = 0;
    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    PMIB_TCP6TABLE_OWNER_PID tcp6Table = nullptr;

    if (family == AF_INET) {
        GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
                std::string localIP = ipToString(&row.dwLocalAddr, AF_INET);
                std::string remoteIP = ipToString(&row.dwRemoteAddr, AF_INET);
                std::string localAddr = localIP + ":" + std::to_string(ntohs((u_short)row.dwLocalPort));
                std::string remoteAddr = remoteIP + ":" + std::to_string(ntohs((u_short)row.dwRemotePort));
                std::string processName = getProcessName(row.dwOwningPid);
                std::string owner = getProcessOwner(row.dwOwningPid);
                std::cout << "|" << std::setw(8) << std::left << "TCP"
                    << "|" << std::setw(24) << std::left << localAddr
                    << "|" << std::setw(24) << std::left << remoteAddr
                    << "|" << std::setw(14) << std::left << stateToString(row.dwState)
                    << "|" << std::setw(8) << std::right << row.dwOwningPid
                    << "|" << std::setw(22) << std::left << processName
                    << "|" << std::setw(30) << std::left << owner << "|\n";
            }
        }
        free(tcpTable);
    }
    else if (family == AF_INET6) {
        GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        tcp6Table = (PMIB_TCP6TABLE_OWNER_PID)malloc(size);
        if (GetExtendedTcpTable(tcp6Table, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcp6Table->dwNumEntries; i++) {
                MIB_TCP6ROW_OWNER_PID row = tcp6Table->table[i];
                std::string localIP = ipToString(&row.ucLocalAddr, AF_INET6);
                std::string remoteIP = ipToString(&row.ucRemoteAddr, AF_INET6);
                std::string localAddr = "[" + localIP + "]:" + std::to_string(ntohs((u_short)row.dwLocalPort));
                std::string remoteAddr = "[" + remoteIP + "]:" + std::to_string(ntohs((u_short)row.dwRemotePort));
                std::string processName = getProcessName(row.dwOwningPid);
                std::string owner = getProcessOwner(row.dwOwningPid);
                std::cout << "|" << std::setw(8) << std::left << "TCP"
                    << "|" << std::setw(24) << std::left << localAddr
                    << "|" << std::setw(24) << std::left << remoteAddr
                    << "|" << std::setw(14) << std::left << stateToString(row.dwState)
                    << "|" << std::setw(8) << std::right << row.dwOwningPid
                    << "|" << std::setw(22) << std::left << processName
                    << "|" << std::setw(30) << std::left << owner << "|\n";
            }
        }
        free(tcp6Table);
    }
}

void printUdpTable(int family) {
    DWORD size = 0;
    PMIB_UDPTABLE_OWNER_PID udpTable = nullptr;
    PMIB_UDP6TABLE_OWNER_PID udp6Table = nullptr;

    if (family == AF_INET) {
        GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (GetExtendedUdpTable(udpTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID row = udpTable->table[i];
                std::string localIP = ipToString(&row.dwLocalAddr, AF_INET);
                std::string localAddr = localIP + ":" + std::to_string(ntohs((u_short)row.dwLocalPort));
                std::string processName = getProcessName(row.dwOwningPid);
                std::string owner = getProcessOwner(row.dwOwningPid);
                std::cout << "|" << std::setw(8) << std::left << "UDP"
                    << "|" << std::setw(24) << std::left << localAddr
                    << "|" << std::setw(24) << std::left << "*.*"
                    << "|" << std::setw(14) << std::left << ""
                    << "|" << std::setw(8) << std::right << row.dwOwningPid
                    << "|" << std::setw(22) << std::left << processName
                    << "|" << std::setw(30) << std::left << owner << "|\n";
            }
        }
        free(udpTable);
    }
    else if (family == AF_INET6) {
        GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        udp6Table = (PMIB_UDP6TABLE_OWNER_PID)malloc(size);
        if (GetExtendedUdpTable(udp6Table, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udp6Table->dwNumEntries; i++) {
                MIB_UDP6ROW_OWNER_PID row = udp6Table->table[i];
                std::string localIP = ipToString(&row.ucLocalAddr, AF_INET6);
                std::string localAddr = "[" + localIP + "]:" + std::to_string(ntohs((u_short)row.dwLocalPort));
                std::string processName = getProcessName(row.dwOwningPid);
                std::string owner = getProcessOwner(row.dwOwningPid);
                std::cout << "|" << std::setw(8) << std::left << "UDP"
                    << "|" << std::setw(24) << std::left << localAddr
                    << "|" << std::setw(24) << std::left << "*.*"
                    << "|" << std::setw(14) << std::left << ""
                    << "|" << std::setw(8) << std::right << row.dwOwningPid
                    << "|" << std::setw(22) << std::left << processName
                    << "|" << std::setw(30) << std::left << owner << "|\n";
            }
        }
        free(udp6Table);
    }
}

void printTableFooter() {
    std::cout << "+" << std::string(8, '-') << "+" << std::string(24, '-') << "+"
        << std::string(24, '-') << "+" << std::string(14, '-') << "+"
        << std::string(8, '-') << "+" << std::string(22, '-') << "+"
        << std::string(30, '-') << "+\n";
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    printTableHeader();
    printTcpTable(AF_INET);
    printTcpTable(AF_INET6);
    printUdpTable(AF_INET);
    printUdpTable(AF_INET6);
    printTableFooter();

    WSACleanup();
    return 0;
}