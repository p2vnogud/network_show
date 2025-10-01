#include <windows.h>
#include <netfw.h>
#include <comutil.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <fstream>

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

// Hàm lấy chuỗi tài nguyên từ file DLL/EXE
std::wstring GetResourceString(const std::wstring& group) {
    if (group.empty() || group[0] != L'@') {
        return group.empty() ? L"None" : group; // Trả về chuỗi gốc nếu không phải tài nguyên
    }

    // Tách tên file và ID tài nguyên
    size_t commaPos = group.find(L',');
    if (commaPos == std::wstring::npos) {
        return group; // Định dạng không hợp lệ
    }

    std::wstring fileName = group.substr(1, commaPos - 1); // Bỏ dấu @
    std::wstring idStr = group.substr(commaPos + 1);
    int resourceId = 0;
    try {
        resourceId = std::stoi(idStr);
    }
    catch (...) {
        return group; // Nếu ID không hợp lệ, trả về chuỗi gốc
    }

    // Tải file DLL/EXE
    HMODULE hModule = LoadLibraryW(fileName.c_str());
    if (!hModule) {
        return group; // Không thể tải file, trả về chuỗi gốc
    }

    // Lấy chuỗi tài nguyên
    WCHAR buffer[256];
    int length = LoadStringW(hModule, abs(resourceId), buffer, sizeof(buffer) / sizeof(WCHAR));
    FreeLibrary(hModule);

    if (length > 0) {
        return std::wstring(buffer, length);
    }
    return group; // Nếu không lấy được chuỗi, trả về chuỗi gốc
}

// Cấu trúc để lưu trữ một rule
struct FirewallRule {
    std::wstring source; // "COM" hoặc "Registry"
    std::wstring name;
    std::wstring description;
    std::wstring direction;
    std::wstring enabled;
    std::wstring action;
    std::wstring program;
    std::wstring group;
    std::wstring profile;
    std::wstring localAddress;
    std::wstring remoteAddress;
    std::wstring localPort;
    std::wstring remotePort;
    std::wstring protocol;
    std::wstring localUserOwner;
};

// Hàm viết rules ra file CSV
void WriteToCSV(const std::vector<FirewallRule>& rules, const std::wstring& filename) {
    std::wofstream csvFile(filename);
    if (!csvFile.is_open()) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcerr << L"Error: Cannot open file " << filename << L" for writing.\n";
        ResetConsoleColor();
        return;
    }

    // Viết header
    csvFile << L"Source,Name,Description,Direction,Enabled,Action,Program,Group,Profile,"
        << L"Local Address,Remote Address,Local Port,Remote Port,Protocol,Local User Owner\n";

    // Viết dữ liệu từng rule
    for (const auto& rule : rules) {
        // Thêm dấu ngoặc kép để xử lý dấu phẩy trong giá trị
        csvFile << L"\"" << rule.source << L"\","
            << L"\"" << rule.name << L"\","
            << L"\"" << rule.description << L"\","
            << L"\"" << rule.direction << L"\","
            << L"\"" << rule.enabled << L"\","
            << L"\"" << rule.action << L"\","
            << L"\"" << rule.program << L"\","
            << L"\"" << rule.group << L"\","
            << L"\"" << rule.profile << L"\","
            << L"\"" << rule.localAddress << L"\","
            << L"\"" << rule.remoteAddress << L"\","
            << L"\"" << rule.localPort << L"\","
            << L"\"" << rule.remotePort << L"\","
            << L"\"" << rule.protocol << L"\","
            << L"\"" << rule.localUserOwner << L"\"\n";
    }

    csvFile.close();
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"Successfully wrote " << rules.size() << L" rules to " << filename << L"\n";
    ResetConsoleColor();
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

// Đọc rule từ Active Store qua COM API và thu thập vào vector
void ListFirewallRules_COM(std::vector<FirewallRule>& allRules) {
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
                FirewallRule rule;
                rule.source = L"COM";

                // In tiêu đề rule
                SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::wcout << L"Rule " << ++index << L" (" << std::setw(3) << index << L"/" << count << L")\n";
                std::wcout << std::wstring(60, L'-') << L"\n";
                ResetConsoleColor();

                // Rule name
                CComBSTR name;
                if (SUCCEEDED(pRule->get_Name(&name))) {
                    rule.name = name.Length() ? std::wstring(name, name.Length()) : L"None";
                    PrintProperty(L"Name", rule.name);
                }

                // Description
                CComBSTR desc;
                if (SUCCEEDED(pRule->get_Description(&desc))) {
                    rule.description = desc.Length() ? std::wstring(desc, desc.Length()) : L"None";
                    PrintProperty(L"Description", rule.description);
                }
                else {
                    rule.description = L"None";
                    PrintProperty(L"Description", rule.description);
                }

                // Direction
                NET_FW_RULE_DIRECTION dir;
                if (SUCCEEDED(pRule->get_Direction(&dir))) {
                    rule.direction = dir == NET_FW_RULE_DIR_IN ? L"In" : L"Out";
                    PrintProperty(L"Direction", rule.direction);
                }

                // Enabled
                VARIANT_BOOL enabled;
                if (SUCCEEDED(pRule->get_Enabled(&enabled))) {
                    rule.enabled = enabled ? L"Yes" : L"No";
                    PrintProperty(L"Enabled", rule.enabled);
                }

                // Action
                NET_FW_ACTION action;
                if (SUCCEEDED(pRule->get_Action(&action))) {
                    rule.action = action == NET_FW_ACTION_ALLOW ? L"Allow" : L"Block";
                    PrintProperty(L"Action", rule.action);
                }

                // Program
                CComBSTR imageFileName;
                if (SUCCEEDED(pRule->get_ApplicationName(&imageFileName))) {
                    rule.program = imageFileName.Length() ? std::wstring(imageFileName, imageFileName.Length()) : L"Any";
                    PrintProperty(L"Program", rule.program);
                }

                // Group
                CComBSTR context;
                if (SUCCEEDED(pRule->get_Grouping(&context))) {
                    std::wstring groupStr = context.Length() ? std::wstring(context, context.Length()) : L"None";
                    rule.group = GetResourceString(groupStr);
                    PrintProperty(L"Group", rule.group);
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
                    rule.profile = profiles.empty() ? L"None" : profiles;
                    PrintProperty(L"Profile", rule.profile);
                }

                // Local Address
                CComBSTR localAddrs;
                if (SUCCEEDED(pRule->get_LocalAddresses(&localAddrs))) {
                    std::wstring addr = localAddrs.Length() ? std::wstring(localAddrs, localAddrs.Length()) : L"Any";
                    rule.localAddress = addr == L"*" ? L"Any" : addr;
                    PrintProperty(L"Local Address", rule.localAddress);
                }

                // Remote Address
                CComBSTR remoteAddrs;
                if (SUCCEEDED(pRule->get_RemoteAddresses(&remoteAddrs))) {
                    std::wstring addr = remoteAddrs.Length() ? std::wstring(remoteAddrs, remoteAddrs.Length()) : L"Any";
                    rule.remoteAddress = addr == L"*" ? L"Any" : addr;
                    PrintProperty(L"Remote Address", rule.remoteAddress);
                }

                // Local Port
                CComBSTR localPorts;
                if (SUCCEEDED(pRule->get_LocalPorts(&localPorts))) {
                    std::wstring ports = localPorts.Length() ? std::wstring(localPorts, localPorts.Length()) : L"Any";
                    rule.localPort = ports == L"*" ? L"Any" : ports;
                    PrintProperty(L"Local Port", rule.localPort);
                }

                // Remote Port
                CComBSTR remotePorts;
                if (SUCCEEDED(pRule->get_RemotePorts(&remotePorts))) {
                    std::wstring ports = remotePorts.Length() ? std::wstring(remotePorts, remotePorts.Length()) : L"Any";
                    rule.remotePort = ports == L"*" ? L"Any" : ports;
                    PrintProperty(L"Remote Port", rule.remotePort);
                }

                // Protocol
                long protocol;
                if (SUCCEEDED(pRule->get_Protocol(&protocol))) {
                    rule.protocol = ProtocolToString(protocol);
                    PrintProperty(L"Protocol", rule.protocol);
                }

                // Local User Owner
                CComPtr<INetFwRule3> pRule3;
                if (SUCCEEDED(pRule->QueryInterface(__uuidof(INetFwRule3), (void**)&pRule3))) {
                    CComBSTR userOwner;
                    if (SUCCEEDED(pRule3->get_LocalUserOwner(&userOwner))) {
                        rule.localUserOwner = userOwner.Length() ? std::wstring(userOwner, userOwner.Length()) : L"Any";
                        PrintProperty(L"Local User Owner", rule.localUserOwner);
                    }
                }

                // Thêm vào vector
                allRules.push_back(rule);
            }
        }
        var.Clear();
    }
}

// Đọc rule từ Local/Domain Policy qua Registry và thu thập vào vector
void ListFirewallRules_Registry(std::vector<FirewallRule>& allRules) {
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

            FirewallRule rule;
            rule.source = L"Registry";

            SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << L"Rule " << index + 1 << L"\n";
            std::wcout << std::wstring(60, L'-') << L"\n";
            ResetConsoleColor();

            // Hiển thị và lưu các thuộc tính
            rule.name = properties[L"Name"].empty() ? ruleName : properties[L"Name"];
            PrintProperty(L"Name", rule.name);

            rule.action = properties[L"Action"].empty() ? L"None" : properties[L"Action"];
            PrintProperty(L"Action", rule.action);

            rule.enabled = properties[L"Active"] == L"TRUE" ? L"Yes" : L"No";
            PrintProperty(L"Enabled", rule.enabled);

            rule.direction = properties[L"Dir"] == L"In" ? L"In" : L"Out";
            PrintProperty(L"Direction", rule.direction);

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
            rule.protocol = protocol;
            PrintProperty(L"Protocol", rule.protocol);

            // Profile
            std::wstring profile = properties[L"Profile"].empty() ? L"None" : properties[L"Profile"];
            if (profile == L"Domain") profile = L"Domain";
            else if (profile == L"Private") profile = L"Private";
            else if (profile == L"Public") profile = L"Public";
            else if (profile.empty()) profile = L"All";
            rule.profile = profile;
            PrintProperty(L"Profile", rule.profile);

            // Local Port
            rule.localPort = properties[L"LPort"].empty() ? L"Any" : properties[L"LPort"];
            PrintProperty(L"Local Port", rule.localPort);

            // Remote Port
            rule.remotePort = properties[L"RPort"].empty() ? L"Any" : properties[L"RPort"];
            PrintProperty(L"Remote Port", rule.remotePort);

            // Remote Address
            std::wstring remoteAddr = L"Any";
            if (!properties[L"RA4"].empty()) {
                remoteAddr = properties[L"RA4"];
                if (!properties[L"RA4Mask"].empty()) {
                    remoteAddr += L"/" + properties[L"RA4Mask"];
                }
            }
            rule.remoteAddress = remoteAddr;
            PrintProperty(L"Remote Address", rule.remoteAddress);

            // Local Address (thường không có trong registry, đặt mặc định là Any)
            rule.localAddress = L"Any";
            PrintProperty(L"Local Address", rule.localAddress);

            // Các trường khác mặc định
            rule.description = L"None";
            rule.program = L"Any";
            rule.group = L"None";
            rule.localUserOwner = L"Any";

            // Thêm vào vector
            allRules.push_back(rule);
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

    std::vector<FirewallRule> allRules;

    ListFirewallRules_COM(allRules);       // Active store
    ListFirewallRules_Registry(allRules);  // Local GPO/Domain GPO store

    // Xuất ra file CSV
    WriteToCSV(allRules, L"firewall_rules.csv");

    CoUninitialize();
    return 0;
}