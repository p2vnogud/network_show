// firewall_rules.cpp
#include <windows.h>
#include <netfw.h>
#include <iostream>
#include <sstream>
// Khi muon dung CCOMPTR
#include <atlbase.h>
#include <atlcomcli.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


std::wstring to_wstring_fallback(long value) {
    std::wstringstream wss;
    wss << value;
    return wss.str();
}

std::wstring ProtocolToString(long proto) {
    switch (proto) {
    case 0:  return L"Any";
    case 1:  return L"ICMPv4";
    case 6:  return L"TCP";
    case 17: return L"UDP";
    case 58: return L"ICMPv6";
    case 256: return L"Any";
    default:
        return L"Other (" + to_wstring_fallback(proto) + L")";
    }
}


void ListFirewallRules_Registry() {
    HKEY hKey;
    LPCWSTR regPath = L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules";

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::wcout << L"[!] No policy-based rules found in registry." << std::endl;
        return;
    }

    DWORD index = 0;
    WCHAR valueName[512];
    DWORD valueNameSize;
    BYTE data[4096];
    DWORD dataSize, type;

    std::wcout << L"\n================ Policy-based Rules (Registry) ================\n" << std::endl;

    while (true) {
        valueNameSize = 512;
        dataSize = sizeof(data);
        LONG ret = RegEnumValueW(hKey, index, valueName, &valueNameSize,
            NULL, &type, data, &dataSize);
        if (ret == ERROR_NO_MORE_ITEMS) break;

        if (ret == ERROR_SUCCESS && type == REG_SZ) {
            std::wstring ruleName(valueName, valueNameSize);
            std::wstring ruleData((wchar_t*)data, dataSize / sizeof(wchar_t) - 1);

            std::wcout << L"-------------------- Rule: " << ruleName << L" --------------------" << std::endl;

            // Tách ruleData theo dấu |
            std::wstringstream ss(ruleData);
            std::wstring token;
            while (std::getline(ss, token, L'|')) {
                if (!token.empty()) {
                    size_t pos = token.find(L'=');
                    if (pos != std::wstring::npos) {
                        std::wstring key = token.substr(0, pos);
                        std::wstring value = token.substr(pos + 1);
                        std::wcout << L"   " << key << L" : " << value << std::endl;
                    }
                    else {
                        std::wcout << L"   " << token << std::endl;
                    }
                }
            }

            std::wcout << L"-------------------------------------------------------------\n" << std::endl;
        }
        index++;
    }

    RegCloseKey(hKey);
}




int wmain() {
    // Khoi tao COM
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"CoInitializeEx failed: " << hr << std::endl;
        return 1;
    }

    // Tạo đối tượng INetFwPolicy2
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) {
        std::wcerr << L"CoCreateInstance for INetFwPolicy2 failed: " << hr << std::endl;
        CoUninitialize();
        return 1;
    }

    // Lấy collection rules
    INetFwRules* pRules = nullptr;
    hr = pNetFwPolicy2->get_Rules(&pRules);
    if (FAILED(hr)) {
        std::wcerr << L"get_Rules failed: " << hr << std::endl;
        pNetFwPolicy2->Release();
        CoUninitialize();
        return 1;
    }

    // Duyệt rule
    IUnknown* pUnk = nullptr;
    IEnumVARIANT* pEnum = nullptr;
    hr = pRules->get__NewEnum(&pUnk);
    if (SUCCEEDED(hr)) {
        hr = pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
        pUnk->Release();
    }

    long count = 0;
    hr = pRules->get_Count(&count);
    std::cout << "=============================================================" << std::endl;
    std::cout << "Số lượng rule firewall là: " << count << std::endl;
    std::cout << "=============================================================\n" << std::endl;

    int index = 0;

    if (SUCCEEDED(hr)) {
        VARIANT var;
        VariantInit(&var);
        while (S_OK == pEnum->Next(1, &var, NULL)) {
            if (var.vt == VT_DISPATCH) {
                INetFwRule* pRule = nullptr;
                hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pRule);
                if (SUCCEEDED(hr)) {
                    std::cout << "********************* Rule " << ++index << " ****************************" << std::endl;

                    // Rule name
                    BSTR name;
                    if (SUCCEEDED(pRule->get_Name(&name))) {
                        std::wcout << L"[+] Rule Name: " << name << std::endl;
                        SysFreeString(name);
                    }

                    // Description
                    BSTR desc;
                    if (SUCCEEDED(pRule->get_Description(&desc))) {
                        if (desc) {
                            std::wcout << L"[+] Description: " << desc << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Description:  None" << std::endl;
                        }
                        
                        SysFreeString(desc);
                    }

                    // Direction
                    NET_FW_RULE_DIRECTION dir;
                    if (SUCCEEDED(pRule->get_Direction(&dir))) {
                        std::wcout << L"[+] Direction: "
                            << (dir == NET_FW_RULE_DIR_IN ? L"In" : L"Out")
                            << std::endl;
                    }

                    // Enabled
                    VARIANT_BOOL enabled;
                    if (SUCCEEDED(pRule->get_Enabled(&enabled))) {
                        std::wcout << L"[+] Enabled:   "
                            << (enabled ? L"Yes" : L"No")
                            << std::endl;
                    }

                    // Action
                    NET_FW_ACTION action;
                    if (SUCCEEDED(pRule->get_Action(&action))) {
                        std::wcout << L"[+] Action:    "
                            << (action == NET_FW_ACTION_ALLOW ? L"Allow" : L"Block")
                            << std::endl;
                    }

                    // Program
                    BSTR imageFileName;
                    if (SUCCEEDED(pRule->get_ApplicationName(&imageFileName))) {
                        if (imageFileName == NULL) {
                            std::wcout << L"[+] Program: Any"
                                << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Program: "
                                << imageFileName << std::endl;
                        }
                        
                    }

                    // Group 
                    BSTR context;
                    hr = pRule->get_Grouping(&context);
                    if (SUCCEEDED(hr)) {
                        if (context) {
                            std::wcout << L"[+] Group: "
                                << context << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Group: None"
                                << std::endl;
                        }
                    }

                    // Profile
                    long profileTypesBitmask;
                    hr = pRule->get_Profiles(&profileTypesBitmask);
                    std::wcout << "Value bitmask: " << profileTypesBitmask << std::endl;
                    if (SUCCEEDED(hr)) {
                        std::wcout << L"[+] Profile: ";

                        if (profileTypesBitmask & NET_FW_PROFILE2_DOMAIN) {
                            std::wcout << L"Domain ";
                        }
                        if (profileTypesBitmask & NET_FW_PROFILE2_PRIVATE) {
                            std::wcout << L"Private ";
                        }
                        if (profileTypesBitmask & NET_FW_PROFILE2_PUBLIC) {
                            std::wcout << L"Public ";
                        }
                        if (profileTypesBitmask == NET_FW_PROFILE2_ALL) {
                            std::wcout << L"(All)";
                        }

                        std::wcout << std::endl;
                    }

                    
                    // Local Address
                    BSTR localAddrs;
                    hr = pRule->get_LocalAddresses(&localAddrs);
                    if (SUCCEEDED(hr)) {
                        if (wcscmp(localAddrs, L"*") == 0) {
                            std::wcout << L"[+] Local Address: Any" << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Local Address: " << localAddrs << std::endl;
                        }

                    }


                    // Remote Address
                    BSTR remoteAddrs;
                    hr = pRule->get_RemoteAddresses(&remoteAddrs);
                    if (SUCCEEDED(hr)) {
                        if (wcscmp(remoteAddrs, L"*") == 0) {
                            std::wcout << L"[+] Remote Address: Any" << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Remote Address: " << remoteAddrs << std::endl;
                        }
                    }

                    // Local Port
                    BSTR portNumbers_local;
                    hr = pRule->get_LocalPorts(&portNumbers_local);
                    std::cout << "port: " << portNumbers_local << std::endl;
                    if (SUCCEEDED(hr)) {
                        if (!portNumbers_local || wcscmp(portNumbers_local, L"*") == 0) {
                            std::wcout << L"[+] Local Port: Any" << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Local Port: " << portNumbers_local << std::endl;
                        }
                    }

                    // Remote Port
                    BSTR portNumbers_remote;
                    hr = pRule->get_RemotePorts(&portNumbers_remote);
                    if (SUCCEEDED(hr)) {
                        if (!portNumbers_remote || wcscmp(portNumbers_remote, L"*") == 0) {
                            std::wcout << L"[+] Remote Port: Any" << std::endl;
                        }
                        else {
                            std::wcout << L"[+] Remote Port: " << portNumbers_remote << std::endl;
                        }
                    }


                    // Local User Owner



                    // Protocol
                    long protocol;
                    hr = pRule->get_Protocol(&protocol);
                    std::wcout << L"Protocol: " << ProtocolToString(protocol) << std::endl;

                    CComPtr<INetFwRule3> pRule3;
                    if (SUCCEEDED(pRule->QueryInterface(__uuidof(INetFwRule3), (void**)&pRule3))) {
                        BSTR userOwner;
                        if (SUCCEEDED(pRule3->get_LocalUserOwner(&userOwner))) {
                            std::wcout << L"   Local User Owner: "
                                << (userOwner ? userOwner : L"Any") << std::endl;
                        }
                    }

                    //INetFwRule3* pRule3 = nullptr;
                    //if (SUCCEEDED(pRule->QueryInterface(__uuidof(INetFwRule3), (void**)&pRule3))) {
                    //    BSTR userOwner;
                    //    if (SUCCEEDED(pRule3->get_LocalUserOwner(&userOwner))) {
                    //        std::wcout << L"[+] Local User Owner: "
                    //            << (userOwner ? userOwner : L"Any") << std::endl;
                    //    }
                    //    pRule3->Release(); // nhớ giải phóng!
                    //}

                    std::wcout << L"---------------------------------------------------------\n" << std::endl;

                    pRule->Release();
                }
            }
            VariantClear(&var);
        }
        pEnum->Release();
    }

    std::wcout << "Rule In Local Group Policy" << std::endl;
    ListFirewallRules_Registry();

    // Cleanup
    pRules->Release();
    pNetFwPolicy2->Release();
    CoUninitialize();

    return 0;
}
