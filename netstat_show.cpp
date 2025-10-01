#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

std::string ipToString(DWORD ip)
{
    struct in_addr inAddr;
    inAddr.S_un.S_addr = ip;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &inAddr, buf, sizeof(buf));
    return std::string(buf);
}

std::string stateToString(DWORD state)
{
    switch (state)
    {
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

int main()
{
    DWORD size = 0;
    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;

    // Lấy kích thước buffer
    GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);

    if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        printf("%-20s %-20s %-12s %-6s\n", "Local Address", "Remote Address", "State", "PID");
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++)
        {
            MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
            std::string localIP = ipToString(row.dwLocalAddr);
            std::string remoteIP = ipToString(row.dwRemoteAddr);

            printf("%s:%d  %-15s:%d  %-12s %6d\n",
                localIP.c_str(), ntohs((u_short)row.dwLocalPort),
                remoteIP.c_str(), ntohs((u_short)row.dwRemotePort),
                stateToString(row.dwState).c_str(),
                row.dwOwningPid);
        }
    }
    else
    {
        std::cerr << "Lỗi khi lấy TCP table\n";
    }

    free(tcpTable);
    return 0;
}
