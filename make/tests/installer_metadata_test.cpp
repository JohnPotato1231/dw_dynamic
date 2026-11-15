// Exercise the real metadata writer in an isolated HKCU test key.
// No services, common Start menu shortcuts, or installed app entries are changed.
#include "../../os_win_service/src/main.h"

static std::wstring testRegistryPath;

static LSTATUS createTestRegistryKey(HKEY, LPCWSTR, PHKEY result) {
    return RegCreateKeyW(HKEY_CURRENT_USER, testRegistryPath.c_str(), result);
}

static HRESULT skipCommonStartMenu(HWND, int, PIDLIST_ABSOLUTE*) {
    return E_FAIL;
}

#define RegCreateKeyW createTestRegistryKey
#define SHGetSpecialFolderLocation skipCommonStartMenu
#define wmain service_entry_point_for_metadata_test
#include "../../os_win_service/src/main.cpp"
#undef wmain
#undef SHGetSpecialFolderLocation
#undef RegCreateKeyW

static bool verifyMetadata(wchar_t* directory, const std::wstring& expectedPublisher) {
    if (!installShortcuts(directory)) return false;
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, testRegistryPath.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return false;
    wchar_t version[64] = {};
    DWORD type = 0, length = sizeof(version);
    bool versionOK = RegQueryValueExW(key, L"DisplayVersion", NULL, &type,
        reinterpret_cast<BYTE*>(version), &length) == ERROR_SUCCESS
        && type == REG_SZ && std::wstring(version) == L"4.8.1907.16384";
    DWORD size = 0;
    length = sizeof(size);
    bool sizeOK = RegQueryValueExW(key, L"EstimatedSize", NULL, &type,
        reinterpret_cast<BYTE*>(&size), &length) == ERROR_SUCCESS
        && type == REG_DWORD && size == 2;
    wchar_t publisher[128] = {};
    length = sizeof(publisher);
    bool publisherOK = RegQueryValueExW(key, L"Publisher", NULL, &type,
        reinterpret_cast<BYTE*>(publisher), &length) == ERROR_SUCCESS
        && type == REG_SZ && std::wstring(publisher) == expectedPublisher
        && length == (expectedPublisher.size() + 1) * sizeof(wchar_t);
    wchar_t displayName[128] = {};
    length = sizeof(displayName);
    bool displayOK = RegQueryValueExW(key, L"DisplayName", NULL, &type,
        reinterpret_cast<BYTE*>(displayName), &length) == ERROR_SUCCESS
        && type == REG_SZ && std::wstring(displayName) == serviceDisplayName;
    RegCloseKey(key);
    return versionOK && sizeOK && publisherOK && displayOK;
}

struct MetadataFixture {
    std::wstring directory;
    std::wstring nativeDirectory;
    std::wstring properties;

    bool create() {
        wchar_t temporaryDirectory[MAX_PATH], temporaryFile[MAX_PATH];
        DWORD length = GetTempPathW(MAX_PATH, temporaryDirectory);
        if (!length || length >= MAX_PATH ||
                !GetTempFileNameW(temporaryDirectory, L"DWM", 0, temporaryFile)) return false;
        directory = temporaryFile;
        if (!DeleteFileW(directory.c_str()) || !CreateDirectoryW(directory.c_str(), NULL)) return false;
        nativeDirectory = directory + L"\\native";
        properties = nativeDirectory + L"\\service.properties";
        return CreateDirectoryW(nativeDirectory.c_str(), NULL) != FALSE;
    }

    bool write(const std::wstring& content) {
        int length = WideCharToMultiByte(CP_UTF8, 0, content.c_str(),
            static_cast<int>(content.size()), NULL, 0, NULL, NULL);
        if (length <= 0) return false;
        std::vector<char> encoded(length);
        if (WideCharToMultiByte(CP_UTF8, 0, content.c_str(),
                static_cast<int>(content.size()), encoded.data(), length, NULL, NULL) != length) return false;
        HANDLE file = CreateFileW(properties.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        bool result = WriteFile(file, encoded.data(), length, &written, NULL) && written == length;
        CloseHandle(file);
        return result;
    }

    ~MetadataFixture() {
        if (!properties.empty()) DeleteFileW(properties.c_str());
        if (!nativeDirectory.empty()) RemoveDirectoryW(nativeDirectory.c_str());
        if (!directory.empty()) RemoveDirectoryW(directory.c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, testRegistryPath.c_str());
    }
};

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 1;
    testRegistryPath = L"Software\\REMO-Installer-Metadata-Test-" + std::to_wstring(GetCurrentProcessId());
    serviceName = L"MetadataFixture";
    serviceDisplayName = L"Metadata Remote Support";
    iconPathForLink[0] = L'\0';
    MetadataFixture fixture;
    if (!fixture.create()) return 2;
    // The default must remain compatible with older four-field profiles.
    if (publisherName != L"DWService" || !verifyMetadata(argv[1], L"DWService")) return 3;
    const std::wstring customPublisher = L"REMO Support \u2014 Z\u00fcrich";
    if (!fixture.write(L"serviceName=MetadataFixture\r\nserviceDisplayName=Metadata Remote Support\r\npublisher="
            + customPublisher + L"\r\n")) return 4;
    workPath = fixture.directory;
    loadProperties();
    if (publisherName != customPublisher || !verifyMetadata(argv[1], customPublisher)) return 5;
    // An empty property must still produce a useful legacy Publisher value.
    if (!fixture.write(L"publisher=\r\n")) return 6;
    loadProperties();
    if (publisherName != L"DWService" || !verifyMetadata(argv[1], L"DWService")) return 7;
    std::wcout << L"PASS: UTF-8 properties select the Unicode publisher; the registry writer preserves defaults, display name, version and calculated size." << std::endl;
    return 0;
}
