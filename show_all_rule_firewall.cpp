#include <windows.h>
#include <netfw.h>
#include <comutil.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>

// Khi muốn dùng CComPtr
#include <atlbase.h>
#include <atlcomcli.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Thêm màu sắc cho console
void SetConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// Đặt lại màu mặc định
void ResetConsoleColor() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// Hàm chuyển đổi số thành chuỗi
std::wstring to_wstring_fallback(long value) {
    std::wstringstream wss;
    wss << value;
    return wss.str();
}

// Hàm chuyển đổi protocol thành chuỗi
std::wstring ProtocolToString(long proto) {
    switch (proto) {
    case 0:   return L"Any";
    case 1:   return L"ICMPv4";
    case 6:   return L"TCP";
    case 17:  return L"UDP";
    case 58:  return L"ICMPv6";
    case 256: return L"Any";
    default:  return L"Other (" + to_wstring_fallback(proto) + L")";
    }
}

// Hàm in tiêu đề với định dạng đẹp
void PrintHeader(const std::wstring& title) {
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"\n" << std::wstring(60, L'=') << L"\n";
    std::wcout << std::left << std::setw(60) << title << L"\n";
    std::wcout << std::wstring(60, L'=') << L"\n";
    ResetConsoleColor();
}

// Hàm in thuộc tính với căn chỉnh cột
void PrintProperty(const std::wstring& name, const std::wstring& value) {
    std::wcout << std::left << std::setw(20) << name << L": " << value << L"\n";
}

// Hàm phân tích chuỗi rule từ Registry
std::map<std::wstring, std::wstring> ParseRegistryRule(const std::wstring& ruleData) {
    std::map<std::wstring, std::wstring> properties;
    std::wstringstream wss(ruleData);
    std::wstring token;

    while (std::getline(wss, token, L'|')) {
        size_t pos = token.find(L'=');
        if (pos != std::wstring::npos) {
            std::wstring key = token.substr(0, pos);
            std::wstring value = token.substr(pos + 1);
            properties[key] = value;
        }
    }
    return properties;
}

// Đọc rule từ Active Store qua COM API
void ListFirewallRules_COM() {
    HRESULT hr = S_OK;

    // Tạo đối tượng INetFwPolicy2
    CComPtr<INetFwPolicy2> pNetFwPolicy2;
    hr = pNetFwPolicy2.CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER);
    if (FAILED(hr)) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcerr << L"Error: CoCreateInstance for INetFwPolicy2 failed: " << hr << L"\n";
        ResetConsoleColor();
        return;
    }

    // Lấy collection rules
    CComPtr<INetFwRules> pRules;
    hr = pNetFwPolicy2->get_Rules(&pRules);
    if (FAILED(hr)) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcerr << L"Error: get_Rules failed: " << hr << L"\n";
        ResetConsoleColor();
        return;
    }

    // Đếm số rule
    long count = 0;
    pRules->get_Count(&count);
    PrintHeader(L"Active Firewall Rules (COM)");
    std::wcout << L"Total Rules: " << count << L"\n\n";

    // Duyệt rule
    CComPtr<IUnknown> pUnk;
    CComPtr<IEnumVARIANT> pEnum;
    hr = pRules->get__NewEnum(&pUnk);
    if (SUCCEEDED(hr)) {
        hr = pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
    }

    if (FAILED(hr)) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcerr << L"Error: Failed to enumerate rules: " << hr << L"\n";
        ResetConsoleColor();
        return;
    }

    int index = 0;
    CComVariant var;
    while (S_OK == pEnum->Next(1, &var, NULL)) {
        if (var.vt == VT_DISPATCH) {
            CComPtr<INetFwRule> pRule;
            hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pRule);
            if (SUCCEEDED(hr)) {
                // In tiêu đề rule
                SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::wcout << L"Rule " << ++index << L" (" << std::setw(3) << index << L"/" << count << L")\n";
                std::wcout << std::wstring(60, L'-') << L"\n";
                ResetConsoleColor();

                // Rule name
                CComBSTR name;
                if (SUCCEEDED(pRule->get_Name(&name))) {
                    PrintProperty(L"Name", name.Length() ? std::wstring(name, name.Length()) : L"None");
                }

                // Description
                CComBSTR desc;
                if (SUCCEEDED(pRule->get_Description(&desc))) {
                    PrintProperty(L"Description", desc.Length() ? std::wstring(desc, desc.Length()) : L"None");
                }
                else {
                    PrintProperty(L"Description", L"None");
                }

                // Direction
                NET_FW_RULE_DIRECTION dir;
                if (SUCCEEDED(pRule->get_Direction(&dir))) {
                    PrintProperty(L"Direction", dir == NET_FW_RULE_DIR_IN ? L"In" : L"Out");
                }

                // Enabled
                VARIANT_BOOL enabled;
                if (SUCCEEDED(pRule->get_Enabled(&enabled))) {
                    PrintProperty(L"Enabled", enabled ? L"Yes" : L"No");
                }

                // Action
                NET_FW_ACTION action;
                if (SUCCEEDED(pRule->get_Action(&action))) {
                    PrintProperty(L"Action", action == NET_FW_ACTION_ALLOW ? L"Allow" : L"Block");
                }

                // Program
                CComBSTR imageFileName;
                if (SUCCEEDED(pRule->get_ApplicationName(&imageFileName))) {
                    PrintProperty(L"Program", imageFileName.Length() ? std::wstring(imageFileName, imageFileName.Length()) : L"Any");
                }

                // Group
                CComBSTR context;
                if (SUCCEEDED(pRule->get_Grouping(&context))) {
                    PrintProperty(L"Group", context.Length() ? std::wstring(context, context.Length()) : L"None");
                }

                // Profile
                long profileTypesBitmask;
                if (SUCCEEDED(pRule->get_Profiles(&profileTypesBitmask))) {
                    std::wstring profiles;
                    if (profileTypesBitmask == NET_FW_PROFILE2_ALL) {
                        profiles = L"All";
                    }
                    else {
                        if (profileTypesBitmask & NET_FW_PROFILE2_DOMAIN) profiles += L"Domain ";
                        if (profileTypesBitmask & NET_FW_PROFILE2_PRIVATE) profiles += L"Private ";
                        if (profileTypesBitmask & NET_FW_PROFILE2_PUBLIC) profiles += L"Public ";
                    }
                    PrintProperty(L"Profile", profiles.empty() ? L"None" : profiles);
                }

                // Local Address
                CComBSTR localAddrs;
                if (SUCCEEDED(pRule->get_LocalAddresses(&localAddrs))) {
                    std::wstring addr = localAddrs.Length() ? std::wstring(localAddrs, localAddrs.Length()) : L"Any";
                    PrintProperty(L"Local Address", addr == L"*" ? L"Any" : addr);
                }

                // Remote Address
                CComBSTR remoteAddrs;
                if (SUCCEEDED(pRule->get_RemoteAddresses(&remoteAddrs))) {
                    std::wstring addr = remoteAddrs.Length() ? std::wstring(remoteAddrs, remoteAddrs.Length()) : L"Any";
                    PrintProperty(L"Remote Address", addr == L"*" ? L"Any" : addr);
                }

                // Local Port
                CComBSTR localPorts;
                if (SUCCEEDED(pRule->get_LocalPorts(&localPorts))) {
                    std::wstring ports = localPorts.Length() ? std::wstring(localPorts, localPorts.Length()) : L"Any";
                    PrintProperty(L"Local Port", ports == L"*" ? L"Any" : ports);
                }

                // Remote Port
                CComBSTR remotePorts;
                if (SUCCEEDED(pRule->get_RemotePorts(&remotePorts))) {
                    std::wstring ports = remotePorts.Length() ? std::wstring(remotePorts, remotePorts.Length()) : L"Any";
                    PrintProperty(L"Remote Port", ports == L"*" ? L"Any" : ports);
                }

                // Protocol
                long protocol;
                if (SUCCEEDED(pRule->get_Protocol(&protocol))) {
                    PrintProperty(L"Protocol", ProtocolToString(protocol));
                }

                // Local User Owner
                CComPtr<INetFwRule3> pRule3;
                if (SUCCEEDED(pRule->QueryInterface(__uuidof(INetFwRule3), (void**)&pRule3))) {
                    CComBSTR userOwner;
                    if (SUCCEEDED(pRule3->get_LocalUserOwner(&userOwner))) {
                        PrintProperty(L"Local User Owner", userOwner.Length() ? std::wstring(userOwner, userOwner.Length()) : L"Any");
                    }
                }
            }
        }
        var.Clear();
    }
}

// Đọc rule từ Local/Domain Policy qua Registry
void ListFirewallRules_Registry() {
    HKEY hKey;
    LPCWSTR regPath = L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules";

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintHeader(L"Policy-based Firewall Rules (Registry)");
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"No policy-based rules found in registry.\n";
        ResetConsoleColor();
        return;
    }

    PrintHeader(L"Policy-based Firewall Rules (Registry)");

    DWORD index = 0;
    WCHAR valueName[512];
    DWORD valueNameSize;
    BYTE data[4096];
    DWORD dataSize, type;

    while (true) {
        valueNameSize = 512;
        dataSize = sizeof(data);
        LONG ret = RegEnumValueW(hKey, index, valueName, &valueNameSize, NULL, &type, data, &dataSize);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret == ERROR_SUCCESS && type == REG_SZ) {
            std::wstring ruleName(valueName, valueNameSize);
            std::wstring ruleData((wchar_t*)data, dataSize / sizeof(wchar_t) - 1);

            // Phân tích chuỗi rule
            auto properties = ParseRegistryRule(ruleData);

            SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << L"Rule " << index + 1 << L"\n";
            std::wcout << std::wstring(60, L'-') << L"\n";
            ResetConsoleColor();

            // Hiển thị các thuộc tính
            PrintProperty(L"Name", properties[L"Name"].empty() ? ruleName : properties[L"Name"]);
            PrintProperty(L"Action", properties[L"Action"].empty() ? L"None" : properties[L"Action"]);
            PrintProperty(L"Enabled", properties[L"Active"] == L"TRUE" ? L"Yes" : L"No");
            PrintProperty(L"Direction", properties[L"Dir"] == L"In" ? L"In" : L"Out");

            // Protocol
            std::wstring protocol = L"Any";
            if (!properties[L"Protocol"].empty()) {
                try {
                    long proto = std::stol(properties[L"Protocol"]);
                    protocol = ProtocolToString(proto);
                }
                catch (...) {
                    protocol = properties[L"Protocol"];
                }
            }
            PrintProperty(L"Protocol", protocol);

            // Profile
            std::wstring profile = properties[L"Profile"].empty() ? L"None" : properties[L"Profile"];
            if (profile == L"Domain") profile = L"Domain";
            else if (profile == L"Private") profile = L"Private";
            else if (profile == L"Public") profile = L"Public";
            else if (profile.empty()) profile = L"All";
            PrintProperty(L"Profile", profile);

            // Local Port
            PrintProperty(L"Local Port", properties[L"LPort"].empty() ? L"Any" : properties[L"LPort"]);

            // Remote Port
            PrintProperty(L"Remote Port", properties[L"RPort"].empty() ? L"Any" : properties[L"RPort"]);

            // Remote Address
            std::wstring remoteAddr = L"Any";
            if (!properties[L"RA4"].empty()) {
                remoteAddr = properties[L"RA4"];
                if (!properties[L"RA4Mask"].empty()) {
                    remoteAddr += L"/" + properties[L"RA4Mask"];
                }
            }
            PrintProperty(L"Remote Address", remoteAddr);

            // Local Address (thường không có trong registry, đặt mặc định là Any)
            PrintProperty(L"Local Address", L"Any");
        }
        index++;
    }

    RegCloseKey(hKey);
}

int wmain() {
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcerr << L"Error: CoInitializeEx failed: " << hr << L"\n";
        ResetConsoleColor();
        return 1;
    }

    ListFirewallRules_COM();       // Active store
    ListFirewallRules_Registry();  // Local GPO/Domain GPO store

    CoUninitialize();
    return 0;
}