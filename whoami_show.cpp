#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

// Hàm chuyển SID thành chuỗi
std::wstring SidToString(PSID sid) {
    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        std::wstring result(sidString);
        LocalFree(sidString);
        return result;
    }
    return L"";
}

// Hàm lấy tên nhóm từ SID
std::wstring GetGroupName(PSID sid, const std::wstring& domain) {
    WCHAR name[256];
    WCHAR dom[256];
    DWORD nameLen = 256;
    DWORD domLen = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(nullptr, sid, name, &nameLen, dom, &domLen, &use)) {
        return std::wstring(dom) + L"\\" + name;
    }
    return L"Unknown";
}

// Hàm lấy mô tả privilege
std::wstring GetPrivilegeDescription(LPWSTR privilegeName) {
    DWORD langId;
    WCHAR desc[256];
    DWORD descLen = 256;
    if (LookupPrivilegeDisplayNameW(nullptr, privilegeName, desc, &descLen, &langId)) {
        return desc;
    }
    return L"Unknown";
}

// Hàm in thông tin người dùng
void PrintUserInformation(HANDLE token) {
    std::wcout << L"USER INFORMATION" << std::endl;
    std::wcout << L"----------------" << std::endl << std::endl;

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        WCHAR username[256];
        WCHAR domain[256];
        DWORD userLen = 256;
        DWORD domLen = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, user->User.Sid, username, &userLen, domain, &domLen, &use)) {
            std::wcout << L"User Name      SID" << std::endl;
            std::wcout << L"============== ==============================================" << std::endl;
            std::wcout << domain << L"\\" << username << L" " << SidToString(user->User.Sid) << std::endl << std::endl;
        }
    }
}

// Hàm in thông tin nhóm
void PrintGroupInformation(HANDLE token) {
    std::wcout << L"GROUP INFORMATION" << std::endl;
    std::wcout << L"-----------------" << std::endl << std::endl;

    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (GetTokenInformation(token, TokenGroups, buffer.data(), size, &size)) {
        TOKEN_GROUPS* groups = reinterpret_cast<TOKEN_GROUPS*>(buffer.data());
        std::wcout << L"Group Name                                 Type             SID          Attributes" << std::endl;
        std::wcout << L"========================================== ================ ============ ==================================================" << std::endl;

        for (DWORD i = 0; i < groups->GroupCount; ++i) {
            std::wstring groupName = GetGroupName(groups->Groups[i].Sid, L"");
            std::wstring sidStr = SidToString(groups->Groups[i].Sid);
            std::wstring type;
            SID_NAME_USE use;
            WCHAR dummy[1];
            DWORD dummyLen = 1;
            LookupAccountSidW(nullptr, groups->Groups[i].Sid, dummy, &dummyLen, dummy, &dummyLen, &use);
            switch (use) {
            case SidTypeWellKnownGroup: type = L"Well-known group"; break;
            case SidTypeAlias: type = L"Alias"; break;
            default: type = L"Group"; break;
            }

            std::wstring attributes;
            if (groups->Groups[i].Attributes & SE_GROUP_MANDATORY) attributes += L"Mandatory group, ";
            if (groups->Groups[i].Attributes & SE_GROUP_ENABLED_BY_DEFAULT) attributes += L"Enabled by default, ";
            if (groups->Groups[i].Attributes & SE_GROUP_ENABLED) attributes += L"Enabled group";
            if (attributes.empty()) attributes = L"None";
            else attributes = attributes.substr(0, attributes.size() - 2); // Xóa dấu phẩy cuối

            std::wcout << std::left << std::setw(42) << groupName
                << std::setw(17) << type
                << std::setw(13) << sidStr
                << attributes << std::endl;
        }
        std::wcout << std::endl;
    }
}

// Hàm in thông tin privileges
void PrintPrivilegesInformation(HANDLE token) {
    std::wcout << L"PRIVILEGES INFORMATION" << std::endl;
    std::wcout << L"----------------------" << std::endl << std::endl;

    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (GetTokenInformation(token, TokenPrivileges, buffer.data(), size, &size)) {
        TOKEN_PRIVILEGES* privs = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
        std::wcout << L"Privilege Name                Description                          State" << std::endl;
        std::wcout << L"============================= ==================================== ========" << std::endl;

        for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
            WCHAR privName[256];
            DWORD privLen = 256;
            LookupPrivilegeNameW(nullptr, &privs->Privileges[i].Luid, privName, &privLen);
            std::wstring desc = GetPrivilegeDescription(privName);
            std::wstring state = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled";

            std::wcout << std::left << std::setw(30) << privName
                << std::setw(37) << desc
                << state << std::endl;
        }
        std::wcout << std::endl;
    }
}

// Hàm in thông tin claims (đơn giản hóa vì thường unknown trong ngữ cảnh này)
void PrintUserClaimsInformation() {
    std::wcout << L"USER CLAIMS INFORMATION" << std::endl;
    std::wcout << L"-----------------------" << std::endl << std::endl;
    std::wcout << L"User claims unknown." << std::endl << std::endl;
    std::wcout << L"Kerberos support for Dynamic Access Control on this device has been disabled." << std::endl << std::endl;
}

// Hàm in thông tin thêm (ví dụ: Integrity Level)
void PrintAdditionalInformation(HANDLE token) {
    std::wcout << L"ADDITIONAL INFORMATION" << std::endl;
    std::wcout << L"----------------------" << std::endl << std::endl;

    // Integrity Level
    DWORD size = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), size, &size)) {
        TOKEN_MANDATORY_LABEL* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
        std::wstring sidStr = SidToString(label->Label.Sid);
        std::wcout << L"Mandatory Integrity Level: " << sidStr << std::endl;

        // Chuyển SID thành level
        if (sidStr == L"S-1-16-4096") std::wcout << L" (Low Mandatory Level)" << std::endl;
        else if (sidStr == L"S-1-16-8192") std::wcout << L" (Medium Mandatory Level)" << std::endl;
        else if (sidStr == L"S-1-16-12288") std::wcout << L" (High Mandatory Level)" << std::endl;
        else if (sidStr == L"S-1-16-16384") std::wcout << L" (System Mandatory Level)" << std::endl;
        else std::wcout << L" (Unknown Level)" << std::endl;
    }

    // Thông tin token khác
    TOKEN_STATISTICS stats;
    size = sizeof(TOKEN_STATISTICS);
    if (GetTokenInformation(token, TokenStatistics, &stats, size, &size)) {
        std::wcout << L"Token ID: " << stats.TokenId.HighPart << L":" << stats.TokenId.LowPart << std::endl;
        std::wcout << L"Authentication ID: " << stats.AuthenticationId.HighPart << L":" << stats.AuthenticationId.LowPart << std::endl;
        std::wcout << L"Expiration Time: " << stats.ExpirationTime.HighPart << L":" << stats.ExpirationTime.LowPart << std::endl;
        std::wcout << L"Token Type: " << (stats.TokenType == TokenPrimary ? L"Primary" : L"Impersonation") << std::endl;
        std::wcout << L"Impersonation Level: " << stats.ImpersonationLevel << std::endl;
        std::wcout << L"Dynamic Charged: " << stats.DynamicCharged << std::endl;
        std::wcout << L"Dynamic Available: " << stats.DynamicAvailable << std::endl;
        std::wcout << L"Group Count: " << stats.GroupCount << std::endl;
        std::wcout << L"Privilege Count: " << stats.PrivilegeCount << std::endl;
        std::wcout << L"Modified ID: " << stats.ModifiedId.HighPart << L":" << stats.ModifiedId.LowPart << std::endl;
    }
    std::wcout << std::endl;
}

int wmain() {
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        PrintUserInformation(token);
        PrintGroupInformation(token);
        PrintPrivilegesInformation(token);
        PrintUserClaimsInformation();
        PrintAdditionalInformation(token);  // Phần thông tin chi tiết hơn
        CloseHandle(token);
    }
    else {
        std::wcout << L"Failed to open process token. Error: " << GetLastError() << std::endl;
    }
    return 0;
}