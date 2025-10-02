#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <iostream>
#include <iomanip>
#include <string>

// Define _WIN32_WINNT for Windows Vista to ensure compatibility with required APIs
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

std::wstring getUserName() {
    WCHAR username[256], domain[256];
    DWORD usernameLen = sizeof(username) / sizeof(WCHAR), domainLen = sizeof(domain) / sizeof(WCHAR);
    SID_NAME_USE sidType;
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return L"Unknown";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return L"Unknown";
    }

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        if (LookupAccountSidW(NULL, pTokenUser->User.Sid, username, &usernameLen, domain, &domainLen, &sidType)) {
            std::wstring result = domainLen > 0 ? std::wstring(domain) + L"\\" + std::wstring(username) : std::wstring(username);
            free(pTokenUser);
            CloseHandle(hToken);
            return result;
        }
    }

    free(pTokenUser);
    CloseHandle(hToken);
    return L"Unknown";
}

std::wstring getSidString(PSID sid) {
    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        std::wstring result(sidString);
        LocalFree(sidString);
        return result;
    }
    return L"Unknown";
}

std::wstring getAccountName(PSID sid) {
    WCHAR name[256], domain[256];
    DWORD nameLen = sizeof(name) / sizeof(WCHAR), domainLen = sizeof(domain) / sizeof(WCHAR);
    SID_NAME_USE sidType;
    if (LookupAccountSidW(NULL, sid, name, &nameLen, domain, &domainLen, &sidType)) {
        if (domain[0] != L'\0') {
            return std::wstring(domain) + L"\\" + std::wstring(name);
        }
        return std::wstring(name);
    }
    return L"Unknown";
}

std::wstring getGroupType(SID_NAME_USE sidType) {
    switch (sidType) {
    case SidTypeUser: return L"User";
    case SidTypeGroup: return L"Group";
    case SidTypeDomain: return L"Domain";
    case SidTypeAlias: return L"Alias";
    case SidTypeWellKnownGroup: return L"Well-known group";
    case SidTypeDeletedAccount: return L"Deleted account";
    case SidTypeInvalid: return L"Invalid";
    case SidTypeUnknown: return L"Unknown";
    case SidTypeComputer: return L"Computer";
    case SidTypeLabel: return L"Label";
    default: return L"Unknown";
    }
}

std::wstring getGroupAttributes(DWORD attributes) {
    std::wstring result;
    if (attributes & SE_GROUP_MANDATORY) result += L"Mandatory group, ";
    if (attributes & SE_GROUP_ENABLED_BY_DEFAULT) result += L"Enabled by default, ";
    if (attributes & SE_GROUP_ENABLED) result += L"Enabled group, ";
    if (attributes & SE_GROUP_USE_FOR_DENY_ONLY) result += L"Group used for deny only, ";
    if (result.empty()) return L"";
    return result.substr(0, result.length() - 2); // Remove trailing comma and space
}

std::wstring getPrivilegeState(DWORD attributes) {
    if (attributes & SE_PRIVILEGE_ENABLED) return L"Enabled";
    if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) return L"Enabled by default";
    return L"Disabled";
}

bool isDomainJoined() {
    LPWSTR domainName = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;
    if (NetGetJoinInformation(NULL, &domainName, &joinStatus) == NERR_Success) {
        bool joined = (joinStatus == NetSetupDomainName);
        if (domainName) NetApiBufferFree(domainName);
        return joined;
    }
    return false;
}

void printUserInfo() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::wcerr << L"Failed to open process token\n";
        return;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return;
    }

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        std::wstring username = getUserName();
        std::wstring sid = getSidString(pTokenUser->User.Sid);

        std::wcout << L"USER INFORMATION\n";
        std::wcout << std::wstring(16, L'=') << L"\n\n";
        std::wcout << std::setw(12) << std::left << L"User Name"
            << std::setw(4) << L" " << std::wstring(45, L'=') << L"\n";
        std::wcout << std::setw(12) << std::left << username
            << std::setw(4) << L" " << sid << L"\n\n";
    }

    free(pTokenUser);
    CloseHandle(hToken);
}

void printGroupInfo() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::wcerr << L"Failed to open process token\n";
        return;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)malloc(dwSize);
    if (!pTokenGroups) {
        CloseHandle(hToken);
        return;
    }

    if (GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
        std::wcout << L"GROUP INFORMATION\n";
        std::wcout << std::wstring(17, L'-') << L"\n\n";
        std::wcout << std::setw(62) << std::left << L"Group Name"
            << std::setw(4) << L" " << std::setw(17) << std::left << L"Type"
            << std::setw(4) << L" " << std::setw(47) << std::left << L"SID"
            << std::setw(4) << L" " << std::left << L"Attributes" << L"\n";
        std::wcout << std::wstring(62, L'=') << L" " << std::wstring(17, L'=') << L" "
            << std::wstring(47, L'=') << L" " << std::wstring(50, L'=') << L"\n";

        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
            SID_NAME_USE sidType;
            WCHAR name[256], domain[256];
            DWORD nameLen = sizeof(name) / sizeof(WCHAR), domainLen = sizeof(domain) / sizeof(WCHAR);
            if (LookupAccountSidW(NULL, pTokenGroups->Groups[i].Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                if (sidType == SidTypeLogonSession) continue; // Skip LogonSessionId groups
                std::wstring groupName = getAccountName(pTokenGroups->Groups[i].Sid);
                std::wstring sid = getSidString(pTokenGroups->Groups[i].Sid);
                std::wstring type = getGroupType(sidType);
                std::wstring attributes = getGroupAttributes(pTokenGroups->Groups[i].Attributes);

                std::wcout << std::setw(62) << std::left << groupName
                    << std::setw(4) << L" " << std::setw(17) << std::left << type
                    << std::setw(4) << L" " << std::setw(47) << std::left << sid
                    << std::setw(4) << L" " << std::left << attributes << L"\n";
            }
        }
        std::wcout << L"\n";
    }

    free(pTokenGroups);
    CloseHandle(hToken);
}

void printPrivilegesInfo() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::wcerr << L"Failed to open process token\n";
        return;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwSize);
    if (!pTokenPrivileges) {
        CloseHandle(hToken);
        return;
    }

    if (GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize)) {
        std::wcout << L"PRIVILEGES INFORMATION\n";
        std::wcout << std::wstring(22, L'-') << L"\n\n";
        std::wcout << std::setw(30) << std::left << L"Privilege Name"
            << std::setw(4) << L" " << std::setw(37) << std::left << L"Description"
            << std::setw(4) << L" " << std::left << L"State" << L"\n";
        std::wcout << std::wstring(30, L'=') << L" " << std::wstring(37, L'=') << L" "
            << std::wstring(10, L'=') << L"\n";

        for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
            WCHAR privName[256];
            DWORD nameLen = sizeof(privName) / sizeof(WCHAR);
            if (LookupPrivilegeNameW(NULL, &pTokenPrivileges->Privileges[i].Luid, privName, &nameLen)) {
                WCHAR displayName[256];
                DWORD displayNameLen = sizeof(displayName) / sizeof(WCHAR);
                DWORD langId;
                LookupPrivilegeDisplayNameW(NULL, privName, displayName, &displayNameLen, &langId);
                std::wstring state = getPrivilegeState(pTokenPrivileges->Privileges[i].Attributes);

                std::wcout << std::setw(30) << std::left << privName
                    << std::setw(4) << L" " << std::setw(37) << std::left << displayName
                    << std::setw(4) << L" " << std::left << state << L"\n";
            }
        }
        std::wcout << L"\n";
    }

    free(pTokenPrivileges);
    CloseHandle(hToken);
}

void printUserClaimsInfo() {
    std::wcout << L"USER CLAIMS INFORMATION\n";
    std::wcout << std::wstring(23, L'-') << L"\n\n";
    if (isDomainJoined()) {
        std::wcout << L"User claims unknown.\n";
        std::wcout << L"Kerberos support for Dynamic Access Control on this device has been disabled.\n";
    }
    else {
        std::wcout << L"User claims unknown.\n";
    }
    std::wcout << L"\n";
}

int main() {
    // Set console output to UTF-8 for proper Unicode support
    SetConsoleOutputCP(CP_UTF8);
    std::wcout.imbue(std::locale(""));

    printUserInfo();
    printGroupInfo();
    printPrivilegesInfo();
    printUserClaimsInfo();

    return 0;
}