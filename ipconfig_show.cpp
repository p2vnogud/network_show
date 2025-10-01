#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include <sstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Hàm chuyển đổi địa chỉ MAC thành chuỗi hex
std::string MacAddressToString(const unsigned char* mac, DWORD length) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (DWORD i = 0; i < length; ++i) {
        if (i > 0) ss << "-";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

// Hàm in địa chỉ IP từ chuỗi sockaddr
void PrintIpAddress(const sockaddr* sa) {
    char buffer[INET6_ADDRSTRLEN];
    if (sa->sa_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, buffer, sizeof(buffer));
    }
    else if (sa->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, buffer, sizeof(buffer));
    }
    else {
        strcpy_s(buffer, "Unknown");
    }
    std::cout << buffer;
}

// Hàm in danh sách địa chỉ (unicast, anycast, multicast, dns, gateway, etc.)
void PrintAddressList(const std::string& label, PIP_ADAPTER_UNICAST_ADDRESS addr) {
    if (!addr) return;
    std::cout << label << std::endl;
    while (addr) {
        std::cout << "           ";
        PrintIpAddress(addr->Address.lpSockaddr);
        std::cout << " / " << static_cast<int>(addr->OnLinkPrefixLength) << std::endl;
        addr = addr->Next;
    }
}

void PrintDnsServerList(PIP_ADAPTER_DNS_SERVER_ADDRESS dns) {
    if (!dns) return;
    std::cout << "DNS Servers . . . . . . . . . . . : " << std::endl;
    while (dns) {
        std::cout << "           ";
        PrintIpAddress(dns->Address.lpSockaddr);
        std::cout << std::endl;
        dns = dns->Next;
    }
}

void PrintGatewayList(PIP_ADAPTER_GATEWAY_ADDRESS gateway) {
    if (!gateway) return;
    std::cout << "Default Gateway . . . . . . . . . : " << std::endl;
    while (gateway) {
        std::cout << "           ";
        PrintIpAddress(gateway->Address.lpSockaddr);
        std::cout << std::endl;
        gateway = gateway->Next;
    }
}

int main() {
    // Khởi tạo Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Allocate buffer cho GetAdaptersAddresses
    ULONG bufferSize = 15000; // Kích thước ban đầu
    std::vector<BYTE> buffer(bufferSize);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;

    // Gọi lần đầu để lấy kích thước buffer cần thiết
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferSize);
    }

    if (result != NO_ERROR) {
        std::cerr << "GetAdaptersAddresses failed with error: " << result << std::endl;
        WSACleanup();
        return 1;
    }

    // In thông tin hệ thống chung (tương tự Host Name, Primary Dns Suffix, etc.)
    char hostname[NI_MAXHOST];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        std::cout << "Host Name . . . . . . . . . . . . : " << hostname << std::endl;
    }

    std::cout << "\n";

    // Lặp qua tất cả các adapter
    for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
        // Bỏ qua adapter không hoạt động hoặc loopback nếu không cần
        if (adapter->OperStatus != IfOperStatusUp && adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK) continue;

        std::cout << "Ethernet adapter " << adapter->FriendlyName << ":" << std::endl;
        std::cout << std::endl;

        std::wcout << "   Description . . . . . . . . . . . : " << adapter->Description << std::endl;
        if (adapter->PhysicalAddressLength > 0) {
            std::cout << "   Physical Address. . . . . . . . . : "
                << MacAddressToString(adapter->PhysicalAddress, adapter->PhysicalAddressLength) << std::endl;
        }
        std::cout << "   DHCP Enabled. . . . . . . . . . . : " << (adapter->Flags & IP_ADAPTER_DHCP_ENABLED ? "Yes" : "No") << std::endl;
        std::cout << "   Autoconfiguration Enabled . . . . : " << (adapter->Flags & IP_ADAPTER_IPV4_ENABLED ? "Yes" : "No") << std::endl;

        // In địa chỉ IPv4 và IPv6
        PrintAddressList("   IP Address. . . . . . . . . . . . : ", adapter->FirstUnicastAddress);

        // In Default Gateway
        PrintGatewayList(adapter->FirstGatewayAddress);

        // DHCP Server
        if (adapter->Dhcpv4Server.iSockaddrLength > 0) {
            std::cout << "   DHCP Server . . . . . . . . . . . : ";
            PrintIpAddress(adapter->Dhcpv4Server.lpSockaddr);
            std::cout << std::endl;
        }

        // DNS Servers
        PrintDnsServerList(adapter->FirstDnsServerAddress);

        // Thêm thông tin bổ sung để trực quan: MTU, IfType, OperStatus
        std::cout << "   Media State . . . . . . . . . . . : "
            << (adapter->OperStatus == IfOperStatusUp ? "Media connected" : "Media disconnected") << std::endl;
        std::cout << "   MTU . . . . . . . . . . . . . . . : " << adapter->Mtu << std::endl;
        std::cout << "   IfType  . . . . . . . . . . . . . : " << adapter->IfType << std::endl;
        std::cout << "   Transmit Link Speed . . . . . . . : " << adapter->TransmitLinkSpeed / 1000000 << " Mbps" << std::endl;
        std::cout << "   Receive Link Speed  . . . . . . . : " << adapter->ReceiveLinkSpeed / 1000000 << " Mbps" << std::endl;

        // DNS Suffix
        if (adapter->DnsSuffix) {
            std::wcout << "   DNS Suffix  . . . . . . . . . . . : " << adapter->DnsSuffix << std::endl;
        }

        std::cout << "\n";
    }

    WSACleanup();
    return 0;
}