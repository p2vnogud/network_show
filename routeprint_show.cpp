#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>  // <-- thêm dòng này để dùng std::unordered_map

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

int main() {
    // 1) Lấy danh sách adapter (để map index -> tên interface)
    ULONG buflen = 15000;
    std::vector<BYTE> bufAd(buflen);
    PIP_ADAPTER_ADDRESSES pAd = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(bufAd.data());
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    DWORD ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAd, &buflen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        bufAd.resize(buflen);
        pAd = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(bufAd.data());
        ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAd, &buflen);
    }
    if (ret != NO_ERROR) {
        std::cerr << "GetAdaptersAddresses failed: " << ret << "\n";
        return 1;
    }

    // map ifIndex -> friendly name
    std::unordered_map<ULONG, std::string> ifIndexToName; // ✅ lỗi ở đây đã được sửa
    for (PIP_ADAPTER_ADDRESSES cur = pAd; cur; cur = cur->Next) {
        if (cur->IfIndex != 0) {
            std::wstring wname(cur->FriendlyName ? cur->FriendlyName : L"");
            std::string name(wname.begin(), wname.end());
            ifIndexToName[cur->IfIndex] = name;
        }
    }

    // 2) Lấy bảng định tuyến IPv4
    PMIB_IPFORWARDTABLE pFwd = nullptr;
    DWORD size = 0;
    DWORD res = GetIpForwardTable(nullptr, &size, FALSE);
    if (res == ERROR_INSUFFICIENT_BUFFER) {
        pFwd = (PMIB_IPFORWARDTABLE)malloc(size);
        res = GetIpForwardTable(pFwd, &size, FALSE);
    }
    if (res != NO_ERROR) {
        std::cerr << "GetIpForwardTable failed: " << res << "\n";
        return 1;
    }

    std::cout << "Network Destination    Netmask          Gateway        Interface        Metric\n";
    std::cout << "-----------------------------------------------------------------------------\n";

    for (DWORD i = 0; i < pFwd->dwNumEntries; ++i) {
        MIB_IPFORWARDROW& r = pFwd->table[i];
        IN_ADDR dest, mask, gw;
        dest.S_un.S_addr = r.dwForwardDest;
        mask.S_un.S_addr = r.dwForwardMask;
        gw.S_un.S_addr = r.dwForwardNextHop;

        char destBuf[16], maskBuf[16], gwBuf[16];
        inet_ntop(AF_INET, &dest, destBuf, sizeof(destBuf));
        inet_ntop(AF_INET, &mask, maskBuf, sizeof(maskBuf));
        inet_ntop(AF_INET, &gw, gwBuf, sizeof(gwBuf));

        std::string ifName = std::to_string(r.dwForwardIfIndex);
        auto it = ifIndexToName.find(r.dwForwardIfIndex);
        if (it != ifIndexToName.end()) ifName = it->second;

        printf("%-21s %-15s %-15s %-15s %u\n",
            destBuf, maskBuf, gwBuf, ifName.c_str(), r.dwForwardMetric1);
    }

    if (pFwd) free(pFwd);
    return 0;
}
