#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

// Global module handle for our DLL.
HMODULE g_hModule = NULL;

//================= Digital Signature Verification Section ===================

// Helper: Given a certificate context, extracts the serial number (in human-readable hex).
// The certificate serial number is stored in little-endian order, so we reverse the bytes.
std::wstring GetCertificateSerialNumber(PCCERT_CONTEXT pCertContext)
{
    if (!pCertContext)
        return L"";

    const CRYPT_INTEGER_BLOB* serialBlob = &pCertContext->pCertInfo->SerialNumber;
    std::wstringstream wss;
    // Reverse the byte order for display.
    for (DWORD i = serialBlob->cbData; i > 0; i--)
    {
        wss << std::hex << std::setw(2) << std::setfill(L'0')
            << static_cast<int>(serialBlob->pbData[i - 1]);
    }
    return wss.str();
}

// Checks whether the file at filePath is signed with a certificate whose serial number matches allowedSerialNumber.
bool IsFileSignedWithSerialNumber(const std::wstring& filePath, const std::wstring& allowedSerialNumber)
{
    // Step 1: Verify the signature using WinVerifyTrust.
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = 0;
    winTrustData.hWVTStateData = NULL;
    winTrustData.pwszURLReference = NULL;
    winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    winTrustData.dwUIContext = 0;
    winTrustData.pFile = &fileData;

    LONG lStatus = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
    if (lStatus != ERROR_SUCCESS)
    {
        // Signature verification failed.
        return false;
    }

    // Step 2: Retrieve certificate information using CryptQueryObject.
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
    BOOL bResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL);
    if (!bResult)
    {
        return false;
    }

    // Step 3: Get the signer info.
    DWORD dwSignerInfo = 0;
    bResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
    if (!bResult)
    {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return false;
    }
    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
    if (!pSignerInfo)
    {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return false;
    }
    bResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo);
    if (!bResult)
    {
        LocalFree(pSignerInfo);
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return false;
    }

    // Step 4: Find the certificate corresponding to the signer.
    CERT_INFO certInfo = { 0 };
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;
    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        (PVOID)&certInfo,
        NULL);
    bool result = false;
    if (pCertContext)
    {
        // Step 5: Extract the certificate's serial number.
        std::wstring fileSerial = GetCertificateSerialNumber(pCertContext);
        // Compare with the allowed serial number (case-insensitive).
        if (_wcsicmp(fileSerial.c_str(), allowedSerialNumber.c_str()) == 0)
        {
            result = true;
        }
        CertFreeCertificateContext(pCertContext);
    }

    LocalFree(pSignerInfo);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);
    return result;
}

// Determines whether a module (by its file path) is allowed based on its signature's certificate serial number.
bool IsModuleAllowedBySignature(const std::wstring& modulePath)
{
    // Replace the allowed serial number below with your desired value.
    // For example, whitelist files signed with certificate serial number "267a74977c25c65a60d8e2150343f787":
    const std::wstring allowedSerialNumber = L"267a74977c25c65a60d8e2150343f787";
    return IsFileSignedWithSerialNumber(modulePath, allowedSerialNumber);
}

// Enumerate all loaded modules and collect those that are not allowed.
std::vector<std::wstring> GetSuspiciousDlls()
{
    std::vector<std::wstring> suspicious;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return suspicious;

    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);
    if (Module32FirstW(hSnapshot, &me))
    {
        do
        {
            // Use the full file path (szExePath) for signature verification.
            if (!IsModuleAllowedBySignature(me.szExePath))
            {
                suspicious.push_back(me.szModule);
            }
        } while (Module32NextW(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);
    return suspicious;
}

//================= Manual Mapping Detection Section ===================

// Checks if a memory region starts with a valid PE header.
bool IsValidPE(LPBYTE address)
{
    // Check for "MZ" header.
    if (address[0] != 'M' || address[1] != 'Z')
        return false;

    // Locate the PE header using the offset stored at 0x3C.
    DWORD peOffset = *(DWORD*)(address + 0x3C);
    // Sanity check: if the offset is unreasonable, return false.
    if (peOffset == 0 || peOffset > 0x1000)
        return false;

    LPBYTE peHeader = address + peOffset;
    // Check for "PE\0\0" signature.
    if (peHeader[0] != 'P' || peHeader[1] != 'E' || peHeader[2] != 0 || peHeader[3] != 0)
        return false;

    return true;
}

// Scans the process memory to detect regions that might be manually mapped modules.
std::vector<LPVOID> ScanMemoryForManualModules()
{
    std::vector<LPVOID> suspiciousRegions;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPBYTE p = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    while (p < (LPBYTE)sysInfo.lpMaximumApplicationAddress)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        // Look for committed memory regions with executable permissions.
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE))
        {
            // If the beginning of the region appears to have a valid PE header, flag it.
            if (IsValidPE((LPBYTE)mbi.BaseAddress))
            {
                suspiciousRegions.push_back(mbi.BaseAddress);
            }
        }
        p += mbi.RegionSize;
    }
    return suspiciousRegions;
}

//================= Logging Section ===================

// Returns the folder path of the current DLL.
std::wstring GetDllFolderPath()
{
    wchar_t path[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(g_hModule, path, MAX_PATH))
    {
        std::wstring fullPath = path;
        size_t pos = fullPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
        {
            return fullPath.substr(0, pos + 1);
        }
    }
    return L"";
}

// Writes detected suspicious DLLs (from module enumeration) to a text file.
void WriteSuspiciousDllsToFile(const std::vector<std::wstring>& suspicious)
{
    std::wstring folder = GetDllFolderPath();
    std::wstring filePath = folder + L"DetectedDLLs.txt";

    // Open the file in append mode.
    std::wofstream file(filePath, std::ios::app);
    if (!file.is_open())
        return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    file << L"--- Module Check at " << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
        << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L" ---\n";
    for (const auto& dllName : suspicious)
    {
        file << dllName << L"\n";
    }
    file << L"\n";
    file.close();
}

// Writes detected manually mapped modules (memory regions) to a text file.
void WriteManualMappedRegionsToFile(const std::vector<LPVOID>& regions)
{
    std::wstring folder = GetDllFolderPath();
    std::wstring filePath = folder + L"DetectedManualMappedModules.txt";

    std::wofstream file(filePath, std::ios::app);
    if (!file.is_open())
        return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    file << L"--- Manual Mapping Check at " << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
        << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L" ---\n";
    for (size_t i = 0; i < regions.size(); i++)
    {
        file << L"Region " << i + 1 << L": " << regions[i] << L"\n";
    }
    file << L"\n";
    file.close();
}

//================= AntiCheat Thread ===================

DWORD WINAPI AntiCheatThread(LPVOID lpParam)
{
    while (true)
    {
        // Check modules via standard enumeration and digital signature verification.
        std::vector<std::wstring> suspiciousDlls = GetSuspiciousDlls();
        if (!suspiciousDlls.empty())
        {
            WriteSuspiciousDllsToFile(suspiciousDlls);
        }

        // Check for manually mapped modules via memory scanning.
        std::vector<LPVOID> manualMappedRegions = ScanMemoryForManualModules();
        if (!manualMappedRegions.empty())
        {
            WriteManualMappedRegionsToFile(manualMappedRegions);
        }

        Sleep(5000); // Check every 5 seconds.
    }
    return 0;
}

//================= DllMain Entry Point ===================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, AntiCheatThread, NULL, 0, NULL);
    }
    return TRUE;
}
