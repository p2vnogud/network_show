#define WIN32_LEAN_AND_MEAN       // Loại bỏ include thừa
#define _WIN32_WINNT 0x0600       // Windows Vista
#define NTDDI_VERSION NTDDI_VISTA // Kích hoạt API Vista+

#include <winsock2.h>
#include <ws2tcpip.h> // Include trước để inet_ntop hoạt động
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <iostream>

// Link với thư viện
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

// Function to convert IPv4 address to string
std::string IpAddrToString(DWORD ipAddr) {
    char buf[16];
    sprintf_s(buf, "%d.%d.%d.%d",
        (ipAddr & 0xFF), (ipAddr >> 8) & 0xFF,
        (ipAddr >> 16) & 0xFF, (ipAddr >> 24) & 0xFF);
    return std::string(buf);
}

// Function to convert IPv6 address to string
std::string Ip6AddrToString(const IN6_ADDR& ipAddr) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipAddr, buf, sizeof(buf)); // Sử dụng inet_ntop trực tiếp
    return std::string(buf);
}

// Function to print IPv4 route table (dùng GetIpForwardTable - an toàn hơn)
void PrintIPv4RouteTable() {
    PMIB_IPFORWARDTABLE pIpForwardTable = nullptr;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    if (GetIpForwardTable(nullptr, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIpForwardTable = (PMIB_IPFORWARDTABLE)malloc(dwSize);
    }

    if (pIpForwardTable == nullptr) {
        printf("Memory allocation failed for IPv4 route table\n");
        return;
    }

    if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, TRUE)) == NO_ERROR) {
        printf("\nIPv4 Route Table\n");
        printf("===========================================================================\n");
        printf("Active Routes:\n");
        printf("%-25s %-25s %-25s %-15s %-10s\n",
            "Network Destination", "Netmask", "Gateway", "Interface", "Metric");

        for (DWORD i = 0; i < pIpForwardTable->dwNumEntries; i++) {
            printf("%-25s %-25s %-25s %-15s %-10lu\n",
                IpAddrToString(pIpForwardTable->table[i].dwForwardDest).c_str(),
                IpAddrToString(pIpForwardTable->table[i].dwForwardMask).c_str(),
                IpAddrToString(pIpForwardTable->table[i].dwForwardNextHop).c_str(),
                IpAddrToString(pIpForwardTable->table[i].dwForwardIfIndex).c_str(),
                pIpForwardTable->table[i].dwForwardMetric1);
        }
        printf("===========================================================================\n");
    }
    else {
        printf("GetIpForwardTable failed with error: %lu\n", dwRetVal);
    }

    free(pIpForwardTable);
}

// Function to print both IPv4 and IPv6 route table using GetIpForwardTable2
void PrintIpForwardTable2(ADDRESS_FAMILY af) {
    PMIB_IPFORWARD_TABLE2 pIpForwardTable2 = nullptr;
    DWORD dwRetVal = 0;

    if ((dwRetVal = GetIpForwardTable2(af, &pIpForwardTable2)) == NO_ERROR) {
        printf("\n%s Route Table\n", (af == AF_INET) ? "IPv4" : "IPv6");
        printf("===========================================================================\n");
        printf("Active Routes:\n");
        printf("%-5s %-30s %-30s %-10s\n",
            "If", "Network Destination", "Gateway", "Metric");

        for (ULONG i = 0; i < pIpForwardTable2->NumEntries; i++) {
            MIB_IPFORWARD_ROW2* row = &pIpForwardTable2->Table[i];
            char dest[INET6_ADDRSTRLEN] = { 0 };
            char gateway[INET6_ADDRSTRLEN] = { 0 };

            if (af == AF_INET) {
                SOCKADDR_IN* destAddr = (SOCKADDR_IN*)&row->DestinationPrefix.Prefix;
                SOCKADDR_IN* gwAddr = (SOCKADDR_IN*)&row->NextHop;
                inet_ntop(AF_INET, &destAddr->sin_addr, dest, sizeof(dest));
                inet_ntop(AF_INET, &gwAddr->sin_addr, gateway, sizeof(gateway));
            }
            else {
                inet_ntop(AF_INET6, &row->DestinationPrefix.Prefix.Ipv6.sin6_addr, dest, sizeof(dest));
                inet_ntop(AF_INET6, &row->NextHop.Ipv6.sin6_addr, gateway, sizeof(gateway));
            }

            printf("%-5lu %-30s %-30s %-10lu\n",
                row->InterfaceIndex,
                dest,
                gateway,
                row->Metric);
        }
        printf("===========================================================================\n");
    }
    else {
        printf("GetIpForwardTable2 failed with error: %lu\n", dwRetVal);
    }

    if (pIpForwardTable2) {
        FreeMibTable(pIpForwardTable2);
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    printf("Interface List\n");
    // Interface list not implemented.

    PrintIPv4RouteTable();
    PrintIpForwardTable2(AF_INET);  // IPv4
    PrintIpForwardTable2(AF_INET6); // IPv6

    WSACleanup();
    return 0;
}