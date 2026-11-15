// Use private fixture directories and mocked process creation. Never launch an
// installer/agent, delete a real installation, or touch a Windows service.
#include "../../os_win_launcher/src/main.h"
#include <iostream>

static DWORD copyError = ERROR_SUCCESS, processError = ERROR_SUCCESS;
static unsigned copied, started, closedProcessHandles;
static std::wstring application, command, workingDirectory;
static DWORD creationFlags;
static std::wstring lockedDirectory;

static BOOL WINAPI fixtureCopyFile(LPCWSTR source, LPCWSTR destination, BOOL failIfExists) {
    ++copied;
    if (!failIfExists) return FALSE;
    if (copyError) {
        SetLastError(copyError);
        return FALSE;
    }
    return CopyFileW(source, destination, failIfExists);
}

static BOOL WINAPI fixtureCreateProcess(LPCWSTR executable, LPWSTR arguments,
        LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD flags, LPVOID,
        LPCWSTR directory, LPSTARTUPINFOW, LPPROCESS_INFORMATION result) {
    ++started;
    application = executable;
    command = arguments;
    workingDirectory = directory;
    creationFlags = flags;
    if (processError) {
        SetLastError(processError);
        return FALSE;
    }
    result->hProcess = reinterpret_cast<HANDLE>(0x11111111);
    result->hThread = reinterpret_cast<HANDLE>(0x22222222);
    return TRUE;
}

static BOOL WINAPI fixtureCloseHandle(HANDLE handle) {
    if (handle == reinterpret_cast<HANDLE>(0x11111111)
            || handle == reinterpret_cast<HANDLE>(0x22222222)) {
        ++closedProcessHandles;
        return TRUE;
    }
    return CloseHandle(handle);
}

static BOOL WINAPI fixtureRemoveDirectory(LPCWSTR directory) {
    if (!lockedDirectory.empty() && lockedDirectory == directory) {
        SetLastError(ERROR_SHARING_VIOLATION);
        return FALSE;
    }
    return RemoveDirectoryW(directory);
}

#define CopyFileW fixtureCopyFile
#define CreateProcessW fixtureCreateProcess
#define CloseHandle fixtureCloseHandle
#define RemoveDirectoryW fixtureRemoveDirectory
#define wmain launcher_entry_point_for_cleanup_test
#include "../../os_win_launcher/src/main.cpp"
#undef wmain

static bool writeFixture(const std::wstring& path, const char* contents) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD length = static_cast<DWORD>(strlen(contents)), written = 0;
    bool result = WriteFile(file, contents, length, &written, NULL) && written == length;
    CloseHandle(file);
    return result;
}

static bool eraseMockedHelper(const std::wstring& executable, const std::wstring& directory) {
    wchar_t temporary[MAX_PATH];
    DWORD length = GetTempPathW(MAX_PATH, temporary);
    if (!length || length >= MAX_PATH || directory.compare(0, length, temporary) != 0
            || executable != directory + L"\\dwaglnc.exe"
            || directory.find(L"\\DWR", length - 1) != length - 1
            || (GetFileAttributesW(directory.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    return DeleteFileW(executable.c_str()) && RemoveDirectoryW(directory.c_str());
}

static bool require(bool value, const char* message) {
    if (!value) std::cerr << "FAIL: " << message << "; Windows error " << GetLastError() << std::endl;
    return value;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 1;
    wchar_t absolute[MAX_PATH], unique[MAX_PATH];
    DWORD length = GetFullPathNameW(argv[1], MAX_PATH, absolute, NULL);
    std::wstring base(absolute);
    if (!length || length >= MAX_PATH || base.find(L"\\make\\tmp\\") == std::wstring::npos
            || base.find(L"launcher-cleanup-fixtures") != base.size() - wcslen(L"launcher-cleanup-fixtures")
            || (GetFileAttributesW(absolute) & FILE_ATTRIBUTE_REPARSE_POINT)) return 2;
    if (!GetTempFileNameW(absolute, L"DWL", 0, unique)
            || !DeleteFileW(unique) || !CreateDirectoryW(unique, NULL)) return 3;
    std::wstring root(unique), native = root + L"\\native", ownerPath = root + L"\\setup-owner.json";
    if (root.compare(0, base.size(), base) != 0 || root[base.size()] != L'\\') return 4;
    if (!CreateDirectoryW(native.c_str(), NULL)
            || !writeFixture(native + L"\\dwaglnc.exe", "private launcher fixture")) return 5;
    if (!require(startRemove(root) && copied == 1 && started == 1 && closedProcessHandles == 2
            && application == workingDirectory + L"\\dwaglnc.exe"
            && command == L"\"" + application + L"\" remove \"" + root + L"\" " + std::to_wstring(GetCurrentProcessId())
            && (creationFlags & CREATE_NO_WINDOW), "cleanup launch uses exact executable, quoted path, hidden window, and closes handles")) return 6;
    std::wstring firstApplication = application, firstDirectory = workingDirectory;
    if (!require(startRemove(root) && application != firstApplication && closedProcessHandles == 4,
            "concurrent cleanup launches use unique temporary locations")) return 7;
    if (!eraseMockedHelper(firstApplication, firstDirectory) || !eraseMockedHelper(application, workingDirectory)) return 8;
    copyError = ERROR_SHARING_VIOLATION;
    if (!require(!startRemove(root) && GetLastError() == ERROR_SHARING_VIOLATION && started == 2,
            "copy failure does not start an obsolete helper")) return 9;
    copyError = ERROR_SUCCESS;
    processError = ERROR_ACCESS_DENIED;
    if (!require(!startRemove(root) && GetLastError() == ERROR_ACCESS_DENIED
            && GetFileAttributesW(application.c_str()) == INVALID_FILE_ATTRIBUTES
            && GetFileAttributesW(workingDirectory.c_str()) == INVALID_FILE_ATTRIBUTES,
            "process launch failure removes private helper and preserves error")) return 10;
    processError = ERROR_SUCCESS;
    const char* owner = "{\"format\":1,\"installation_id\":\"old-generation\"}";
    if (!writeFixture(ownerPath, owner)) return 11;
    BY_HANDLE_FILE_INFORMATION identity = {};
    std::string snapshot;
    if (!require(cleanupDirectoryIdentity(root, identity) && cleanupOwnerContents(root, snapshot)
            && cleanupGenerationMatches(root, identity, snapshot, true), "matching directory and ownership generation is accepted")) return 12;
    if (!writeFixture(ownerPath, "{\"format\":1,\"installation_id\":\"new-generation\"}")) return 13;
    if (!require(!cleanupGenerationMatches(root, identity, snapshot, true), "in-place replacement stops stale cleanup")) return 14;
    if (!writeFixture(ownerPath, owner)) return 15;
    std::wstring previous = root + L"-previous";
    if (!MoveFileW(root.c_str(), previous.c_str()) || !CreateDirectoryW(root.c_str(), NULL)
            || !writeFixture(ownerPath, owner)) return 16;
    bool recreatedRejected = !cleanupGenerationMatches(root, identity, snapshot, true);
    if (!DeleteFileW(ownerPath.c_str()) || !RemoveDirectoryW(root.c_str())
            || !MoveFileW(previous.c_str(), root.c_str())) return 17;
    if (!require(recreatedRejected, "new folder with same pathname and owner contents stops stale cleanup")) return 18;
    std::wstring lockedPath = root + L"\\locked.bin";
    if (!writeFixture(lockedPath, "locked fixture")) return 19;
    HANDLE locked = CreateFileW(lockedPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (locked == INVALID_HANDLE_VALUE) return 20;
    bool partial = !deleteDir(root.c_str(), true);
    bool markerPreserved = cleanupGenerationMatches(root, identity, snapshot, true);
    CloseHandle(locked);
    if (!require(partial && markerPreserved, "locked file retry preserves ownership generation")) return 21;
    lockedDirectory = root;
    bool ownerRemoved = false;
    bool finalDirectoryLocked = !deleteDir(root.c_str(), true, &ownerRemoved);
    bool retryAllowed = cleanupGenerationMatches(root, identity, snapshot, true, ownerRemoved);
    if (!writeFixture(ownerPath, "{\"format\":1,\"installation_id\":\"replacement-after-last-file\"}")) return 23;
    bool newerOwnerRejected = !cleanupGenerationMatches(root, identity, snapshot, true, ownerRemoved);
    if (!DeleteFileW(ownerPath.c_str())) return 24;
    lockedDirectory.clear();
    if (!require(finalDirectoryLocked && ownerRemoved && retryAllowed && newerOwnerRejected,
            "directory lock retries after own marker removal but still rejects a replacement marker")) return 25;
    if (!require(deleteDir(root.c_str(), true, &ownerRemoved) && GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES,
            "retry removes fixture after file and directory locks are released")) return 26;
    wchar_t executable[] = L"fixture", remove[] = L"remove", driveRoot[] = L"C:\\";
    wchar_t* rootArguments[] = {executable, remove, driveRoot};
    if (!require(launcher_entry_point_for_cleanup_test(3, rootArguments) == 2, "drive root is rejected before cleanup")) return 27;
    std::cout << "PASS: cleanup helper launch errors, unique temp copies, stale generations, locked-file retries, and root rejection are isolated and verified." << std::endl;
    return 0;
}
