#include <iostream>
#include <windows.h>
#include <winldap.h>
#include <ntdsapi.h>
#include <winber.h>
#include <sddl.h>
#include <vector>
#include <fcntl.h>
#include <io.h>
#include <iomanip>
#include <sstream>
#include <string>

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "advapi32.lib")

namespace LDAPUtils
{

    // Hàm chuyển đổi FILETIME sang định dạng giống ldp.exe
    std::wstring ConvertFileTimeToLocal(ULONGLONG fileTimeTicks)
    {
        FILETIME fileTime;
        fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
        fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

        SYSTEMTIME utcSystemTime;
        FileTimeToSystemTime(&fileTime, &utcSystemTime);

        SYSTEMTIME localTime;
        TIME_ZONE_INFORMATION tzInfo;
        GetTimeZoneInformation(&tzInfo);
        SystemTimeToTzSpecificLocalTime(&tzInfo, &utcSystemTime, &localTime);

        std::wstringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << localTime.wMonth << L"/"
           << std::setw(2) << localTime.wDay << L"/" << localTime.wYear << L" "
           << std::setw(2) << localTime.wHour << L":" << std::setw(2) << localTime.wMinute << L":"
           << std::setw(2) << localTime.wSecond << L" " << (localTime.wHour < 12 ? L"AM" : L"PM") << L" SE Asia Standard Time";
        return ss.str();
    }

    // Hàm chuyển đổi thời gian LDAP sang định dạng giống ldp.exe (với múi giờ địa phương)
    std::wstring ConvertLDAPTimeToLocal(const std::wstring &ldapTime)
    {
        if (ldapTime.empty())
            return L"";
        // LDAP time: YYYYMMDDHHMMSS.0Z -> FILETIME
        ULARGE_INTEGER fileTime;
        SYSTEMTIME utcSystemTime = {0};
        utcSystemTime.wYear = std::stoi(ldapTime.substr(0, 4));
        utcSystemTime.wMonth = std::stoi(ldapTime.substr(4, 2));
        utcSystemTime.wDay = std::stoi(ldapTime.substr(6, 2));
        utcSystemTime.wHour = std::stoi(ldapTime.substr(8, 2));
        utcSystemTime.wMinute = std::stoi(ldapTime.substr(10, 2));
        utcSystemTime.wSecond = std::stoi(ldapTime.substr(12, 2));

        SYSTEMTIME localTime;
        TIME_ZONE_INFORMATION tzInfo;
        GetTimeZoneInformation(&tzInfo);
        SystemTimeToTzSpecificLocalTime(&tzInfo, &utcSystemTime, &localTime);

        std::wstringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << localTime.wMonth << L"/"
           << std::setw(2) << localTime.wDay << L"/" << localTime.wYear << L" "
           << std::setw(2) << localTime.wHour << L":" << std::setw(2) << localTime.wMinute << L":"
           << std::setw(2) << localTime.wSecond << L" " << (localTime.wHour < 12 ? L"AM" : L"PM") << L" SE Asia Standard Time";
        return ss.str();
    }

    // Hàm chuyển đổi ticks (negative 100-ns intervals) sang DD:HH:MM:SS
    std::wstring ConvertTicksToDuration(LONGLONG ticks)
    {
        ticks = -ticks; // Chuyển sang positive
        LONGLONG seconds = ticks / 10000000;
        int days = static_cast<int>(seconds / 86400);
        int hours = static_cast<int>((seconds % 86400) / 3600);
        int minutes = static_cast<int>((seconds % 3600) / 60);
        int secs = static_cast<int>(seconds % 60);
        std::wstringstream ss;
        ss << days << L":" << std::setfill(L'0') << std::setw(2) << hours << L":"
           << std::setw(2) << minutes << L":" << std::setw(2) << secs;
        return ss.str();
    }

    // Hàm thêm chú thích cho flags
    std::wstring GetInstanceTypeDescription(int value)
    {
        std::wstring desc;
        if (value & 0x1)
            desc += L"IS_NC_HEAD | ";
        if (value & 0x4)
            desc += L"WRITE | ";
        if (!desc.empty())
            desc = L"= ( " + desc.substr(0, desc.length() - 3) + L" )";
        return desc;
    }

    std::wstring GetSystemFlagsDescription(int value)
    {
        std::wstring desc;
        if (value & 0x80000000)
            desc += L"DISALLOW_DELETE | ";
        if (value & 0x4000000)
            desc += L"DOMAIN_DISALLOW_RENAME | ";
        if (value & 0x8000000)
            desc += L"DOMAIN_DISALLOW_MOVE | ";
        if (!desc.empty())
            desc = L"= ( " + desc.substr(0, desc.length() - 3) + L" )";
        return desc;
    }

    std::wstring GetPwdPropertiesDescription(int value)
    {
        return L"= (  )"; // Nếu value = 0, rỗng; thêm logic nếu cần
    }

    // Hàm chuyển đổi dSASignature (binary) sang string giống ldp.exe
    std::wstring ConvertDSASignature(const unsigned char *data, ULONG length)
    {
        if (length < 5)
            return L"";
        int flags = data[0];
        int latency = *(int *)(data + 4);
        GUID dsaGuid = *(GUID *)(data + 8);
        wchar_t guidStr[39];
        StringFromGUID2(dsaGuid, guidStr, 39);
        std::wstringstream ss;
        ss << L"{ V1: Flags = 0x" << std::hex << flags << L"; LatencySecs = " << latency << L"; DsaGuid = " << guidStr << L" }";
        return ss.str();
    }

    // Hàm chuyển đổi objectGUID
    std::wstring ConvertGUIDToString(const unsigned char *guid, ULONG length)
    {
        if (length != 16)
            return L"Invalid GUID";
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        ss << std::setw(2) << (int)guid[3] << std::setw(2) << (int)guid[2] << std::setw(2) << (int)guid[1] << std::setw(2) << (int)guid[0] << L"-"
           << std::setw(2) << (int)guid[5] << std::setw(2) << (int)guid[4] << L"-"
           << std::setw(2) << (int)guid[7] << std::setw(2) << (int)guid[6] << L"-"
           << std::setw(2) << (int)guid[8] << std::setw(2) << (int)guid[9] << L"-";
        for (int i = 10; i < 16; i++)
            ss << std::setw(2) << (int)guid[i];
        return ss.str();
    }

    // Hàm chuyển đổi objectSid
    std::wstring ConvertSIDToString(const unsigned char *sid, ULONG length)
    {
        PSID psid = (PSID)sid;
        LPWSTR sidString = NULL;
        if (ConvertSidToStringSidW(psid, &sidString))
        {
            std::wstring result(sidString);
            LocalFree(sidString);
            return result;
        }
        return L"Invalid SID";
    }

    class LDAPConnection
    {
    private:
        LDAP *ldapConnection;

    public:
        LDAPConnection(const std::wstring &serverAddress, ULONG port = LDAP_PORT)
        {
            ldapConnection = ldap_initW(const_cast<PWSTR>(serverAddress.c_str()), port);
            if (ldapConnection == NULL)
            {
                std::cerr << "Khởi tạo LDAP thất bại." << std::endl;
            }
        }

        ~LDAPConnection()
        {
            Disconnect();
        }

        bool Connect(const std::wstring &username,
                     const std::wstring &password,
                     const std::wstring &domain)
        {
            if (ldapConnection == NULL)
                return false;

            ULONG version = LDAP_VERSION3;
            ULONG returnCode = ldap_set_option(ldapConnection, LDAP_OPT_PROTOCOL_VERSION, (void *)&version);
            if (returnCode != LDAP_SUCCESS)
            {
                std::cerr << "Không thể đặt phiên bản giao thức LDAP: " << returnCode << std::endl;
                return false;
            }

            SEC_WINNT_AUTH_IDENTITY_W authIdent;
            ZeroMemory(&authIdent, sizeof(authIdent));
            authIdent.User = (unsigned short *)username.c_str();
            authIdent.UserLength = static_cast<unsigned long>(username.length());
            authIdent.Password = (unsigned short *)password.c_str();
            authIdent.PasswordLength = static_cast<unsigned long>(password.length());
            authIdent.Domain = (unsigned short *)domain.c_str();
            authIdent.DomainLength = static_cast<unsigned long>(domain.length());
            authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

            returnCode = ldap_bind_sW(ldapConnection, NULL, (PWCHAR)&authIdent, LDAP_AUTH_NEGOTIATE);
            if (returnCode != LDAP_SUCCESS)
            {
                std::cerr << "Kết nối LDAP thất bại. Mã lỗi: " << returnCode << std::endl;
                return false;
            }
            return true;
        }

        void Disconnect()
        {
            if (ldapConnection != NULL)
            {
                ldap_unbind(ldapConnection);
                ldapConnection = NULL;
            }
        }

        void Search(const std::wstring &baseDN,
                    const std::wstring &objectClass,
                    const std::vector<std::wstring> &attributes,
                    const std::wstring &extraFilter = L"")
        {
            if (ldapConnection == NULL)
            {
                std::cerr << "Chưa kết nối với LDAP." << std::endl;
                return;
            }

            LDAPMessage *pSearchResult = NULL;
            std::wstring filter = L"(objectClass=" + objectClass + L")";
            if (!extraFilter.empty())
            {
                filter = L"(&" + filter + extraFilter + L")";
            }

            std::vector<PWCHAR> attrList;
            for (const auto &attr : attributes)
            {
                attrList.push_back(const_cast<PWCHAR>(attr.c_str()));
            }
            attrList.push_back(NULL);

            std::wcout << L"***Searching..." << std::endl;
            std::wcout << L"ldap_search_s(ld, \"" << baseDN << L"\", 0, \"" << filter << L"\", attrList,  0, &msg)" << std::endl;

            ULONG returnCode = ldap_search_sW(
                ldapConnection,
                const_cast<PWSTR>(baseDN.c_str()),
                // LDAP_SCOPE_BASE, // Giữ BASE theo yêu cầu
                LDAP_SCOPE_SUBTREE,
                const_cast<PWSTR>(filter.c_str()),
                attributes.empty() ? NULL : attrList.data(),
                0,
                &pSearchResult);

            if (returnCode != LDAP_SUCCESS)
            {
                std::wcerr << L"Lỗi tìm kiếm LDAP. Mã lỗi: " << returnCode << std::endl;
                std::wcerr << L"Chi tiết lỗi: " << LdapGetLastError() << std::endl;
                return;
            }

            int entryCount = ldap_count_entries(ldapConnection, pSearchResult);
            std::wcout << L"Getting " << entryCount << L" entries:" << std::endl;

            if (entryCount == 0)
            {
                std::wcout << L"Không tìm thấy entry nào khớp với bộ lọc." << std::endl;
                ldap_msgfree(pSearchResult);
                return;
            }

            LDAPMessage *pEntry = ldap_first_entry(ldapConnection, pSearchResult);
            while (pEntry != NULL)
            {
                PWCHAR dn = ldap_get_dnW(ldapConnection, pEntry);
                if (dn != NULL)
                {
                    std::wcout << L"Dn: " << dn << std::endl;
                    ldap_memfree(dn);
                }

                BerElement *pBer = NULL;
                PWCHAR attribute = ldap_first_attributeW(ldapConnection, pEntry, &pBer);
                while (attribute != NULL)
                {
                    PWCHAR *vals = ldap_get_valuesW(ldapConnection, pEntry, attribute);
                    struct berval **bvals = ldap_get_values_lenW(ldapConnection, pEntry, attribute);
                    int valCount = ldap_count_valuesW(vals);
                    std::wcout << attribute;
                    if (valCount > 1)
                        std::wcout << L" (" << valCount << L")";
                    std::wcout << L": ";

                    for (int i = 0; vals && vals[i] != NULL; i++)
                    {
                        std::wstring attrName(attribute);
                        bool isBinary = (bvals && bvals[i] && bvals[i]->bv_len > 0 && vals[i][0] == '\0'); // Kiểm tra binary chính xác hơn
                        std::wstringstream output;

                        if (isBinary)
                        {
                            if (attrName == L"dSASignature")
                            {
                                output << ConvertDSASignature((unsigned char *)bvals[i]->bv_val, bvals[i]->bv_len);
                            }
                            else
                            {
                                output << L"<ldp: Binary blob " << bvals[i]->bv_len << L" bytes>";
                            }
                        }
                        else
                        {
                            output << vals[i];
                        }

                        // Thêm chú thích đặc biệt mà không in gốc trước
                        if (attrName == L"whenCreated" || attrName == L"whenChanged")
                        {
                            output.str(L""); // Xóa output cũ, chỉ in định dạng
                            output << ConvertLDAPTimeToLocal(vals[i]);
                        }
                        else if (attrName == L"creationTime")
                        {
                            output.str(L"");
                            ULONGLONG ticks = _wtoi64(vals[i]);
                            output << ConvertFileTimeToLocal(ticks);
                        }
                        else if (attrName == L"objectGUID")
                        {
                            output.str(L"");
                            if (bvals && bvals[i])
                                output << ConvertGUIDToString((unsigned char *)bvals[i]->bv_val, bvals[i]->bv_len);
                        }
                        else if (attrName == L"objectSid")
                        {
                            output.str(L"");
                            if (bvals && bvals[i])
                                output << ConvertSIDToString((unsigned char *)bvals[i]->bv_val, bvals[i]->bv_len);
                        }
                        else if (attrName == L"instanceType")
                        {
                            output.str(L"");
                            int value = std::stoi(vals[i]);
                            output << L"0x" << std::hex << value << L" " << GetInstanceTypeDescription(value);
                        }
                        else if (attrName == L"systemFlags")
                        {
                            output.str(L"");
                            int value = std::stoi(vals[i]);
                            output << L"0x" << std::hex << value << L" " << GetSystemFlagsDescription(value);
                        }
                        else if (attrName == L"pwdProperties")
                        {
                            output.str(L"");
                            int value = std::stoi(vals[i]);
                            output << L"0x" << std::hex << value << L" " << GetPwdPropertiesDescription(value);
                        }
                        else if (attrName == L"forceLogoff")
                        {
                            output << L" (never)";
                        }
                        else if (attrName == L"lockoutDuration" || attrName == L"lockOutObservationWindow")
                        {
                            output.str(L"");
                            LONGLONG ticks = _wtoi64(vals[i]);
                            output << ConvertTicksToDuration(ticks);
                        }
                        else if (attrName == L"maxPwdAge" || attrName == L"minPwdAge")
                        {
                            output.str(L"");
                            LONGLONG ticks = _wtoi64(vals[i]);
                            output << ConvertTicksToDuration(ticks);
                        }
                        else if (attrName == L"dSCorePropagationData")
                        {
                            output.str(L"");
                            output << L"0x0 = (  )";
                        }

                        std::wcout << output.str();
                        if (i < valCount - 1)
                            std::wcout << L"; ";
                    }
                    std::wcout << L";" << std::endl;

                    if (vals)
                        ldap_value_freeW(vals);
                    if (bvals)
                        ldap_value_free_len(bvals);
                    ldap_memfree(attribute);
                    attribute = ldap_next_attributeW(ldapConnection, pEntry, pBer);
                }

                if (pBer)
                    ber_free(pBer, 0);
                pEntry = ldap_next_entry(ldapConnection, pEntry);
            }

            ldap_msgfree(pSearchResult);
        }
    };
}

int main()
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    std::wstring serverAddress = L"";
    std::wstring username = L"";
    std::wstring password = L"";
    std::wstring dn = L"CN=Users,DC=labrecon,DC=com";
    std::wstring objectClass = L"*"; // Giữ theo yêu cầu

    LDAPUtils::LDAPConnection ldap(serverAddress);

    if (ldap.Connect(username, password, serverAddress))
    {
        std::wcout << L"Kết nối thành công với máy chủ LDAP." << std::endl;

        ldap.Search(
            dn,
            objectClass,
            {L"*"} // Lấy tất cả attributes
        );
    }
    else
    {
        std::wcerr << L"Kết nối với máy chủ LDAP thất bại." << std::endl;
    }

    return 0;
}