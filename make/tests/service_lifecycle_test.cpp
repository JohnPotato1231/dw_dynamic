// Exercise the actual Windows uninstall lifecycle without touching a service,
// common shortcut, installed application, or machine registry key.
#include "../../os_win_service/src/main.h"

static std::vector<DWORD> openResults, queryStates, queryErrors, controlResults;
static size_t openIndex, queryIndex, controlIndex;
static DWORD elapsed, managerError, deletionError;
static unsigned controls, deletions, serviceHandles, closedHandles;
static bool polledBeforeClose;
static LSTATUS registryOpenResult, registryDeleteValueResult, registryDeleteKeyResult;
static DWORD fileDeleteError, directoryDeleteError;
static HRESULT folderResult;
static int requestedFolder;
static unsigned fileDeletes, directoryDeletes, registryValueDeletes, registryKeyDeletes;
static std::wstring deletedFile, deletedKey, deletedValue;
static bool useRealRegistrationTree = false;
static std::wstring registryFixturePath;

static DWORD nextResult(const std::vector<DWORD>& values, size_t& index) {
    if (values.empty()) return ERROR_SUCCESS;
    DWORD result = values[std::min(index, values.size() - 1)];
    ++index;
    return result;
}

static SC_HANDLE WINAPI fixtureOpenSCManager(LPCWSTR, LPCWSTR, DWORD) {
    if (managerError) {
        SetLastError(managerError);
        return NULL;
    }
    return reinterpret_cast<SC_HANDLE>(1);
}

static SC_HANDLE WINAPI fixtureOpenService(SC_HANDLE, LPCWSTR, DWORD access) {
    if (deletions && serviceHandles) polledBeforeClose = true;
    DWORD result = nextResult(openResults, openIndex);
    if (result) {
        SetLastError(result);
        return NULL;
    }
    ++serviceHandles;
    return reinterpret_cast<SC_HANDLE>(2);
}

static BOOL WINAPI fixtureCloseServiceHandle(SC_HANDLE service) {
    ++closedHandles;
    if (service == reinterpret_cast<SC_HANDLE>(2)) {
        if (!serviceHandles) return FALSE;
        --serviceHandles;
    }
    return TRUE;
}

static BOOL WINAPI fixtureQueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE,
        LPBYTE buffer, DWORD, LPDWORD needed) {
    size_t index = std::min(queryIndex, queryStates.size() - 1);
    DWORD error = queryErrors.empty() ? ERROR_SUCCESS
        : queryErrors[std::min(queryIndex, queryErrors.size() - 1)];
    ++queryIndex;
    if (error) {
        SetLastError(error);
        return FALSE;
    }
    SERVICE_STATUS_PROCESS* status = reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer);
    *status = SERVICE_STATUS_PROCESS();
    status->dwCurrentState = queryStates[index];
    status->dwWaitHint = 1000;
    *needed = sizeof(*status);
    return TRUE;
}

static BOOL WINAPI fixtureControlService(SC_HANDLE, DWORD control, LPSERVICE_STATUS status) {
    if (control != SERVICE_CONTROL_STOP) return FALSE;
    ++controls;
    DWORD error = nextResult(controlResults, controlIndex);
    if (error) {
        SetLastError(error);
        return FALSE;
    }
    *status = SERVICE_STATUS();
    status->dwCurrentState = SERVICE_STOP_PENDING;
    return TRUE;
}

static BOOL WINAPI fixtureDeleteService(SC_HANDLE) {
    ++deletions;
    if (deletionError) {
        SetLastError(deletionError);
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI fixtureGetTickCount() { return elapsed; }
static void WINAPI fixtureSleep(DWORD interval) { elapsed += interval; }

static LSTATUS WINAPI fixtureRegOpenKeyEx(HKEY, LPCWSTR, DWORD, REGSAM access, PHKEY result) {
    if (access != KEY_SET_VALUE) return ERROR_ACCESS_DENIED;
    *result = reinterpret_cast<HKEY>(3);
    return registryOpenResult;
}
static LSTATUS WINAPI fixtureRegDeleteValue(HKEY, LPCWSTR name) {
    ++registryValueDeletes;
    deletedValue = name;
    return registryDeleteValueResult;
}
static LSTATUS WINAPI fixtureRegDeleteTree(HKEY, LPCWSTR key) {
    ++registryKeyDeletes;
    deletedKey = key;
    if (useRealRegistrationTree) {
        if (deletedKey != L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LifecycleFixture")
            return ERROR_INVALID_PARAMETER;
        return RegDeleteTreeW(HKEY_CURRENT_USER, (registryFixturePath + L"\\LifecycleFixture").c_str());
    }
    return registryDeleteKeyResult;
}
static LSTATUS WINAPI fixtureRegCloseKey(HKEY) { return ERROR_SUCCESS; }

static HRESULT WINAPI fixtureGetSpecialFolderLocation(HWND, int folder, LPITEMIDLIST* result) {
    requestedFolder = folder;
    *result = reinterpret_cast<LPITEMIDLIST>(4);
    return folderResult;
}
static BOOL WINAPI fixtureGetPathFromIDList(PCIDLIST_ABSOLUTE, LPWSTR result) {
    wcscpy(result, requestedFolder == CSIDL_COMMON_PROGRAMS ? L"C:\\MockPrograms" : L"C:\\MockStartup");
    return TRUE;
}
static void WINAPI fixtureCoTaskMemFree(LPVOID) {}
static BOOL WINAPI fixtureDeleteFile(LPCWSTR path) {
    ++fileDeletes;
    deletedFile = path;
    if (fileDeleteError) {
        SetLastError(fileDeleteError);
        return FALSE;
    }
    return TRUE;
}
static BOOL WINAPI fixtureRemoveDirectory(LPCWSTR) {
    ++directoryDeletes;
    if (directoryDeleteError) {
        SetLastError(directoryDeleteError);
        return FALSE;
    }
    return TRUE;
}

#undef OpenSCManager
#define OpenSCManager fixtureOpenSCManager
#define OpenServiceW fixtureOpenService
#define CloseServiceHandle fixtureCloseServiceHandle
#define QueryServiceStatusEx fixtureQueryServiceStatusEx
#define ControlService fixtureControlService
#define DeleteService fixtureDeleteService
#define GetTickCount fixtureGetTickCount
#define Sleep fixtureSleep
#define RegOpenKeyExW fixtureRegOpenKeyEx
#define RegDeleteValueW fixtureRegDeleteValue
#define RegDeleteTreeW fixtureRegDeleteTree
#define RegCloseKey fixtureRegCloseKey
#define SHGetSpecialFolderLocation fixtureGetSpecialFolderLocation
#define SHGetPathFromIDListW fixtureGetPathFromIDList
#define CoTaskMemFree fixtureCoTaskMemFree
#define DeleteFileW fixtureDeleteFile
#define RemoveDirectoryW fixtureRemoveDirectory
#define wmain service_entry_point_for_lifecycle_test
#include "../../os_win_service/src/main.cpp"
#undef wmain
#undef RegOpenKeyExW
#undef RegDeleteTreeW
#undef RegCloseKey

static void reset() {
    openResults = {ERROR_SUCCESS};
    queryStates = {SERVICE_STOPPED};
    queryErrors.clear();
    controlResults.clear();
    openIndex = queryIndex = controlIndex = 0;
    elapsed = managerError = deletionError = 0;
    controls = deletions = serviceHandles = closedHandles = 0;
    polledBeforeClose = false;
    registryOpenResult = registryDeleteValueResult = registryDeleteKeyResult = ERROR_SUCCESS;
    fileDeleteError = directoryDeleteError = ERROR_SUCCESS;
    folderResult = S_OK;
    requestedFolder = 0;
    fileDeletes = directoryDeletes = registryValueDeletes = registryKeyDeletes = 0;
    deletedFile.clear();
    deletedKey.clear();
    deletedValue.clear();
    serviceName = L"LifecycleFixture";
    SetLastError(ERROR_SUCCESS);
}

static bool require(bool result, const char* label) {
    if (!result) std::cerr << "FAIL: " << label << "; Windows error " << GetLastError() << std::endl;
    return result;
}

int wmain() {
    wchar_t name[] = L"LifecycleFixture";
    wchar_t monitorName[] = L"LifecycleFixtureMon";
    reset();
    if (!require(stopService(name) && controls == 0 && serviceHandles == 0, "already stopped succeeds")) return 1;
    reset();
    queryStates = {SERVICE_STOP_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED};
    if (!require(stopService(name) && controls == 0 && elapsed == 200, "pending stop waits without another stop control")) return 2;
    reset();
    queryStates = {SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED};
    if (!require(stopService(name) && controls == 1 && elapsed == 300, "delayed stop waits until stopped")) return 3;
    reset();
    queryStates = {SERVICE_START_PENDING, SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_STOPPED};
    if (!require(stopService(name) && controls == 1, "starting service transitions then stops")) return 4;
    reset();
    queryStates = {SERVICE_PAUSED, SERVICE_STOPPED};
    if (!require(stopService(name) && controls == 1, "paused service stops")) return 5;
    reset();
    queryStates = {SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_STOPPED};
    controlResults = {ERROR_SERVICE_CANNOT_ACCEPT_CTRL};
    if (!require(stopService(name) && controls == 1, "concurrent stop control race recovers")) return 6;
    reset();
    queryStates = {SERVICE_RUNNING};
    controlResults = {ERROR_SERVICE_NOT_ACTIVE};
    if (!require(stopService(name) && controls == 1, "service stops between status and control")) return 7;
    reset();
    openResults = {ERROR_SERVICE_DOES_NOT_EXIST};
    if (!require(stopService(name) && controls == 0, "absent service stop is idempotent")) return 8;
    reset();
    openResults = {ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_DOES_NOT_EXIST};
    if (!require(stopService(name) && elapsed == 250 && serviceHandles == 0, "stop waits for concurrent deletion")) return 9;
    reset();
    queryStates = {SERVICE_STOP_PENDING};
    if (!require(!stopService(name) && GetLastError() == ERROR_TIMEOUT && elapsed == 60000
            && serviceHandles == 0, "stuck stop has a bounded timeout")) return 10;
    reset();
    queryErrors = {ERROR_ACCESS_DENIED};
    if (!require(!stopService(name) && GetLastError() == ERROR_ACCESS_DENIED && controls == 0
            && serviceHandles == 0, "status permission error is preserved")) return 11;
    reset();
    queryStates = {SERVICE_RUNNING};
    controlResults = {ERROR_DEPENDENT_SERVICES_RUNNING};
    if (!require(!stopService(name) && GetLastError() == ERROR_DEPENDENT_SERVICES_RUNNING,
            "genuine stop error is not hidden")) return 12;
    reset();
    managerError = ERROR_ACCESS_DENIED;
    if (!require(!stopService(name) && GetLastError() == ERROR_ACCESS_DENIED, "manager permission failure is preserved")) return 13;
    reset();
    openResults = {ERROR_SUCCESS, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_DOES_NOT_EXIST};
    if (!require(deleteService(name) && deletions == 1 && !polledBeforeClose && serviceHandles == 0
            && elapsed == 500, "delete releases handle and waits for actual absence")) return 14;
    reset();
    openResults = {ERROR_SERVICE_DOES_NOT_EXIST};
    if (!require(deleteService(name) && deletions == 0, "absent deletion is idempotent")) return 15;
    reset();
    openResults = {ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_DOES_NOT_EXIST};
    if (!require(deleteService(name) && deletions == 0 && elapsed == 250, "already pending deletion finishes")) return 16;
    reset();
    deletionError = ERROR_SERVICE_MARKED_FOR_DELETE;
    openResults = {ERROR_SUCCESS, ERROR_SERVICE_DOES_NOT_EXIST};
    if (!require(deleteService(name) && !polledBeforeClose, "concurrent delete request is idempotent")) return 17;
    reset();
    openResults = {ERROR_SUCCESS, ERROR_SERVICE_MARKED_FOR_DELETE};
    if (!require(!deleteService(name) && GetLastError() == ERROR_TIMEOUT && elapsed == 60000
            && serviceHandles == 0, "stuck deletion fails with bounded timeout")) return 18;
    reset();
    deletionError = ERROR_ACCESS_DENIED;
    if (!require(!deleteService(name) && GetLastError() == ERROR_ACCESS_DENIED && serviceHandles == 0,
            "delete permission failure is preserved")) return 19;
    reset();
    fileDeleteError = directoryDeleteError = ERROR_FILE_NOT_FOUND;
    registryDeleteKeyResult = ERROR_FILE_NOT_FOUND;
    if (!require(removeShortcuts() && fileDeletes == 1 && directoryDeletes == 1 && registryKeyDeletes == 1,
            "missing shortcuts and uninstall registration are idempotent")) return 20;
    reset();
    if (!require(removeShortcuts() && deletedFile == L"C:\\MockPrograms\\LifecycleFixture\\LifecycleFixture.lnk"
            && deletedKey == L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LifecycleFixture",
            "cleanup uses only exact own shortcut and registry key")) return 21;
    reset();
    fileDeleteError = ERROR_SHARING_VIOLATION;
    registryDeleteKeyResult = ERROR_ACCESS_DENIED;
    if (!require(!removeShortcuts() && GetLastError() == ERROR_SHARING_VIOLATION && registryKeyDeletes == 1,
            "shortcut failure does not skip registry cleanup or hide first error")) return 22;
    reset();
    directoryDeleteError = ERROR_DIR_NOT_EMPTY;
    if (!require(removeShortcuts() && GetLastError() == ERROR_SUCCESS && registryKeyDeletes == 1 && fileDeletes == 1,
            "own link and registration removed while unrelated shortcut directory files are retained")) return 23;
    reset();
    registryDeleteValueResult = ERROR_FILE_NOT_FOUND;
    fileDeleteError = ERROR_PATH_NOT_FOUND;
    if (!require(removeAutoRun(monitorName) && registryValueDeletes == 1 && fileDeletes == 1,
            "missing autorun entries are idempotent")) return 24;
    reset();
    if (!require(removeAutoRun(monitorName) && registryValueDeletes == 1 && fileDeletes == 1
            && deletedValue == monitorName && deletedFile == L"C:\\MockStartup\\LifecycleFixture.lnk",
            "both registry and legacy startup link are removed")) return 25;
    reset();
    registryOpenResult = ERROR_ACCESS_DENIED;
    if (!require(!removeAutoRun(monitorName) && GetLastError() == ERROR_ACCESS_DENIED && fileDeletes == 1,
            "autorun permission failure still attempts legacy cleanup")) return 26;
    reset();
    folderResult = E_ACCESSDENIED;
    if (!require(!removeShortcuts() && GetLastError() == ERROR_ACCESS_DENIED && fileDeletes == 0
            && registryKeyDeletes == 1, "shell folder errors remain actionable")) return 27;
    // Verify the real registry API handles descendant keys, without using HKLM.
    reset();
    registryFixturePath = L"Software\\REMO-Native-Lifecycle-Test-" + std::to_wstring(GetCurrentProcessId())
        + L"-" + std::to_wstring(GetTickCount64());
    HKEY ownKey = NULL, neighborKey = NULL;
    LSTATUS ownCreated = RegCreateKeyExW(HKEY_CURRENT_USER,
        (registryFixturePath + L"\\LifecycleFixture\\Child\\Grandchild").c_str(), 0, NULL, 0,
        KEY_ALL_ACCESS, NULL, &ownKey, NULL);
    LSTATUS neighborCreated = RegCreateKeyExW(HKEY_CURRENT_USER,
        (registryFixturePath + L"\\Keep").c_str(), 0, NULL, 0,
        KEY_ALL_ACCESS, NULL, &neighborKey, NULL);
    if (ownKey) RegCloseKey(ownKey);
    if (neighborKey) RegCloseKey(neighborKey);
    useRealRegistrationTree = true;
    bool removed = ownCreated == ERROR_SUCCESS && neighborCreated == ERROR_SUCCESS && removeShortcuts();
    HKEY check = NULL;
    LSTATUS ownAbsent = RegOpenKeyExW(HKEY_CURRENT_USER,
        (registryFixturePath + L"\\LifecycleFixture").c_str(), 0, KEY_READ, &check);
    if (check) RegCloseKey(check);
    check = NULL;
    LSTATUS neighborRemains = RegOpenKeyExW(HKEY_CURRENT_USER,
        (registryFixturePath + L"\\Keep").c_str(), 0, KEY_READ, &check);
    if (check) RegCloseKey(check);
    useRealRegistrationTree = false;
    RegDeleteTreeW(HKEY_CURRENT_USER, registryFixturePath.c_str());
    if (!require(removed && ownAbsent == ERROR_FILE_NOT_FOUND && neighborRemains == ERROR_SUCCESS,
            "registration descendants are removed while neighboring app remains")) return 28;
    reset();
    directoryDeleteError = ERROR_ACCESS_DENIED;
    if (!require(!removeShortcuts() && GetLastError() == ERROR_ACCESS_DENIED && registryKeyDeletes == 1,
            "genuine shortcut directory permission failure remains visible")) return 29;
    std::cout << "PASS: 29 isolated lifecycle scenarios cover stop/delete races, bounded waits, missing entries, and genuine cleanup errors." << std::endl;
    return 0;
}
