#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

void PrintPersistentDefaultRoute(
    const std::wstring& ifGuid,
    const std::wstring& gw,
    const std::wstring& metric,
    const std::wstring& ip,
    const std::wstring& mask,
    bool persistent
) {
    std::wcout
        << L"[Interface] " << ifGuid
        << L" | IP=" << ip
        << L" | Mask=" << mask
        << L" | Gateway=" << gw
        << L" | Metric=" << metric
        << L" | Persistent=" << (persistent ? L"Yes" : L"No")
        << std::endl;
}

void EnumInterfaceGateways() {
    HKEY hIfs;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        0, KEY_READ, &hIfs) != ERROR_SUCCESS) return;

    DWORD i = 0;
    WCHAR subKey[256];
    DWORD subLen;

    while (true) {
        subLen = 256;
        if (RegEnumKeyExW(hIfs, i, subKey, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

        std::wstring ifKey = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
        ifKey += subKey;

        HKEY h;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifKey.c_str(), 0, KEY_READ, &h) == ERROR_SUCCESS) {
            WCHAR buf[1024];
            DWORD sz;

            auto getStr = [&](const wchar_t* name) -> std::wstring {
                sz = sizeof(buf);
                if (RegQueryValueExW(h, name, nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS)
                    return buf;
                return L"";
                };

            std::wstring gw = getStr(L"DefaultGateway");
            std::wstring dhcpGw = getStr(L"DhcpDefaultGateway");
            std::wstring metric = getStr(L"DefaultGatewayMetric");
            std::wstring ip = getStr(L"IPAddress");
            if (ip.empty()) ip = getStr(L"DhcpIPAddress"); // fallback
            std::wstring mask = getStr(L"SubnetMask");
            if (mask.empty()) mask = getStr(L"DhcpSubnetMask");

            if (!gw.empty()) {
                PrintPersistentDefaultRoute(subKey, gw, metric, ip, mask, true);
            }
            else if (!dhcpGw.empty()) {
                PrintPersistentDefaultRoute(subKey, dhcpGw, metric, ip, mask, false);
            }

            RegCloseKey(h);
        }
        i++;
    }

    RegCloseKey(hIfs);
}

void EnumPersistentRoutes() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::wcout << L"No manual persistent routes found.\n";
        return;
    }

    DWORD i = 0;
    WCHAR valueName[1024];
    DWORD valueNameLen;
    BYTE data[1024];
    DWORD dataSize, type;

    std::wcout << L"\n=== Manual Persistent Routes (route -p add) ===\n";

    while (true) {
        valueNameLen = 1024;
        dataSize = sizeof(data);
        if (RegEnumValueW(hKey, i, valueName, &valueNameLen, nullptr, &type, data, &dataSize) != ERROR_SUCCESS) break;

        if (type == REG_SZ) {
            std::wstring entry = valueName; // chính ValueName mới chứa route
            std::wstringstream ss(entry);
            std::wstring dest, mask, gw, metric;
            ss >> dest >> mask >> gw >> metric;

            std::wcout << L"Dest=" << dest
                << L" | Mask=" << mask
                << L" | Gateway=" << gw
                << L" | Metric=" << metric
                << L" | Persistent=Yes (Manual)\n";
        }

        i++;
    }

    RegCloseKey(hKey);
}

int wmain() {
    std::wcout << L"=== Scan for Default Gateways (Persistent & DHCP) ===\n";
    EnumInterfaceGateways();

    std::wcout << L"\n=== Scan Registry PersistentRoutes Key ===\n";
    EnumPersistentRoutes();

    return 0;
}
