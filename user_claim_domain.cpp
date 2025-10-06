#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <lm.h>
#include <iomanip>

#pragma comment(lib, "netapi32.lib")  // For domain join check
#pragma comment(lib, "advapi32.lib")  // For token and registry APIs

void PrintError(const char* msg) {
    DWORD err = GetLastError();
    std::cerr << msg << " (LastError=" << err << ")\n";
}

// Hàm trích xuất tên thân thiện từ Claim ID
std::wstring GetFriendlyNameFromClaimId(const std::wstring& claimId) {
    // Claim ID có dạng "ad://ext/<name>:<GUID>"
    size_t prefixPos = claimId.find(L"ad://ext/");
    if (prefixPos != std::wstring::npos) {
        size_t nameStart = prefixPos + 9; // Bỏ qua "ad://ext/"
        size_t colonPos = claimId.find(L":", nameStart);
        if (colonPos != std::wstring::npos) {
            return claimId.substr(nameStart, colonPos - nameStart);
        }
    }
    // Nếu không tìm thấy, trả về Claim ID gốc
    return claimId;
}

void PrintClaimAttributeV1Array(PCLAIM_SECURITY_ATTRIBUTE_V1 attrs, DWORD count) {
    // In tiêu đề bảng giống whoami /all
    std::wcout << L"Claim Name                                    Claim ID                             Flags Type            Values\n";
    std::wcout << L"============= ================================ ===== ================= =========\n";

    for (DWORD i = 0; i < count; ++i) {
        PCLAIM_SECURITY_ATTRIBUTE_V1 a = &attrs[i];
        std::wstring claimId = a->Name ? a->Name : L"(null)";
        std::wstring friendlyName = GetFriendlyNameFromClaimId(claimId);

        // Xác định loại giá trị
        std::wstring valueType;
        switch (a->ValueType) {
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
            valueType = L"Int64";
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
            valueType = L"UInt64";
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
            valueType = L"String";
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
            valueType = L"Boolean";
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
            valueType = L"SID";
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
            valueType = L"Octet String";
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
            valueType = L"FQBN";
            break;
        default:
            valueType = L"Unknown (" + std::to_wstring(a->ValueType) + L")";
            break;
        }

        // In thông tin claim
        std::wcout << std::left << std::setw(14) << friendlyName
            << std::setw(33) << claimId
            << L" " << std::setw(5) << std::hex << a->Flags << std::dec
            << L" " << std::setw(15) << valueType;

        if (a->ValueCount == 0) {
            std::wcout << L" (no values)\n";
            continue;
        }

        // In giá trị
        switch (a->ValueType) {
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
            for (DWORD v = 0; v < a->ValueCount; ++v) {
                std::wcout << (v == 0 ? L" " : L"                                             ") << a->Values.pInt64[v] << L"\n";
            }
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
            for (DWORD v = 0; v < a->ValueCount; ++v) {
                std::wcout << (v == 0 ? L" " : L"                                             ") << a->Values.pUint64[v] << L"\n";
            }
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
            for (DWORD v = 0; v < a->ValueCount; ++v) {
                PWSTR s = a->Values.ppString[v];
                std::wcout << (v == 0 ? L" " : L"                                             ") << (s ? s : L"(null)") << L"\n";
            }
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
            for (DWORD v = 0; v < a->ValueCount; ++v) {
                ULONGLONG val = a->Values.pUint64[v];
                std::wcout << (v == 0 ? L" " : L"                                             ") << (val ? L"TRUE" : L"FALSE") << L"\n";
            }
            break;
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN:
            for (DWORD v = 0; v < a->ValueCount; ++v) {
                auto oct = a->Values.pOctetString[v];
                std::wcout << (v == 0 ? L" " : L"                                             ") << L"OCTET (size=" << oct.ValueLength << L") : ";
                BYTE* p = reinterpret_cast<BYTE*>(oct.pValue);
                if (!p) { std::wcout << L"(null)\n"; continue; }
                for (DWORD b = 0; b < oct.ValueLength; ++b) {
                    wchar_t buf[8];
                    swprintf_s(buf, L"%02X ", p[b]);
                    std::wcout << buf;
                }
                std::wcout << L"\n";
            }
            break;
        default:
            std::wcout << L" (unsupported value type " << a->ValueType << L")\n";
            break;
        } // switch
    } // for each attribute
}

bool QueryAndPrintTokenClaims(HANDLE hToken, TOKEN_INFORMATION_CLASS infoClass, const wchar_t* desc) {
    DWORD needed = 0;
    // First call to get buffer size
    if (!GetTokenInformation(hToken, infoClass, nullptr, 0, &needed)) {
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            if (err == ERROR_NOT_SUPPORTED) {
                std::wcout << desc << L": Not supported on this OS/token\n";
                return false;
            }
            PrintError("GetTokenInformation size query failed");
            return false;
        }
    }

    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(hToken, infoClass, buffer.data(), needed, &needed)) {
        PrintError("GetTokenInformation failed");
        return false;
    }

    CLAIM_SECURITY_ATTRIBUTES_INFORMATION* pInfo = reinterpret_cast<CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(buffer.data());
    if (!pInfo) {
        std::wcout << desc << L": no claims info (null)\n";
        return false;
    }

    if (pInfo->AttributeCount == 0) {
        std::wcout << desc << L": User has no claims.\n";
        return true;
    }

    if (pInfo->Version != CLAIM_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1) {
        std::wcout << desc << L": unexpected version " << pInfo->Version << L"\n";
    }

    PCLAIM_SECURITY_ATTRIBUTE_V1 pAttrs = pInfo->Attribute.pAttributeV1;
    if (!pAttrs) {
        std::wcout << desc << L": no attribute pointers\n";
        return true;
    }

    std::wcout << desc << L":\n";
    PrintClaimAttributeV1Array(pAttrs, pInfo->AttributeCount);
    return true;
}

// Hàm kiểm tra máy đã join domain hay chưa
bool IsMachineInDomain() {
    LPWSTR domainName = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;
    NET_API_STATUS status = NetGetJoinInformation(nullptr, &domainName, &joinStatus);

    if (status == NERR_Success) {
        if (joinStatus == NetSetupDomainName) {
            std::wcout << L"Machine is joined to domain: " << domainName << std::endl;
            NetApiBufferFree(domainName);
            return true;
        }
        else {
            std::wcout << L"Machine is not joined to a domain." << std::endl;
            NetApiBufferFree(domainName);
            return false;
        }
    }
    else {
        std::wcout << L"Failed to check domain join status. Error: " << status << std::endl;
        return false;
    }
}

// Hàm kiểm tra trạng thái Kerberos/DAC qua registry
bool IsKerberosDacEnabled() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
        0, KEY_QUERY_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        // Nếu key không tồn tại, Kerberos/DAC được coi là tắt
        return false;
    }

    DWORD enableCbacAndArmor = 0;
    DWORD dataSize = sizeof(DWORD);
    result = RegQueryValueExW(hKey, L"EnableCbacAndArmor", nullptr, nullptr, (LPBYTE)&enableCbacAndArmor, &dataSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        // Nếu không đọc được giá trị, coi như Kerberos/DAC tắt
        return false;
    }

    return enableCbacAndArmor == 1;
}

int wmain() {
    // Kiểm tra trạng thái domain
    std::wcout << L"Checking domain join status...\n";
    bool isInDomain = IsMachineInDomain();

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        PrintError("OpenProcessToken failed");
        return 1;
    }

    // Query user claims
    std::wcout << L"\n";
    QueryAndPrintTokenClaims(hToken, TokenUserClaimAttributes, L"USER CLAIMS INFORMATION");

    // Query device claims
    std::wcout << L"\n";
    QueryAndPrintTokenClaims(hToken, TokenDeviceClaimAttributes, L"DEVICE CLAIMS INFORMATION");

    CloseHandle(hToken);

    // Kiểm tra Kerberos support chỉ khi máy đã join domain
    if (isInDomain) {
        std::wcout << L"\n";
        if (IsKerberosDacEnabled()) {
            std::wcout << L"Kerberos support for Dynamic Access Control is enabled.\n";
        }
        else {
            std::wcout << L"Kerberos support for Dynamic Access Control is disabled.\n";
        }
    }

    return 0;
}