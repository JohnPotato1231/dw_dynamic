// Exercise the production extractor without launching setup or installing services.
#include <cstdio>

#define wmain installer_entry_point_for_extraction_test
#include "../../os_win_installer/src/main.cpp"
#undef wmain

static bool isAbsolutePath(const std::wstring& path) {
    return (path.size() >= 3 && path[1] == L':'
        && (path[2] == L'\\' || path[2] == L'/'))
        || (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\');
}

static bool isEmptyDirectory(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES
        || !(attributes & FILE_ATTRIBUTE_DIRECTORY)
        || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return false;
    }
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW((path + L"\\*").c_str(), &entry);
    if (search == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    do {
        if (wcscmp(entry.cFileName, L".") != 0
            && wcscmp(entry.cFileName, L"..") != 0) {
            FindClose(search);
            return false;
        }
    } while (FindNextFileW(search, &entry));
    DWORD error = GetLastError();
    FindClose(search);
    return error == ERROR_NO_MORE_FILES;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        std::fwprintf(stderr, L"Usage: installer_extraction_test.exe <absolute win.7z> <absolute empty directory>\n");
        return 1;
    }
    const std::wstring archive = argv[1];
    const std::wstring destination = argv[2];
    if (!isAbsolutePath(archive) || !isAbsolutePath(destination)
        || !isEmptyDirectory(destination)) {
        std::fwprintf(stderr, L"Expected an absolute archive path and an existing empty, ordinary destination directory.\n");
        return 2;
    }

    const bool modernWindows = isWin10OrLater();
    std::wprintf(L"Production OS detection: %lu.%lu, Windows 10 or later: %ls\n",
        m_osVerInfo.dwMajorVersion, m_osVerInfo.dwMinorVersion,
        modernWindows ? L"yes" : L"no");
    if (!modernWindows) {
        std::fwprintf(stderr, L"This regression check requires Windows 10 or later and the installer manifest.\n");
        return 3;
    }
    if (!SetCurrentDirectoryW(destination.c_str())) {
        std::fwprintf(stderr, L"Cannot enter extraction directory: %lu\n", GetLastError());
        return 4;
    }
    if (!decompressFile(archive, false)) {
        std::fwprintf(stderr, L"Production outer archive extraction failed.\n");
        return 5;
    }
    const std::wstring runtimeArchive = modernWindows ? L"runtimepy3.7z" : L"runtimepy2.7z";
    if (!decompressFile(runtimeArchive, false)) {
        std::fwprintf(stderr, L"Production runtime extraction failed: %ls\n", runtimeArchive.c_str());
        return 6;
    }
    const std::wstring runtimeExecutable = is64BitWindows()
        ? L"runtimepy3\\bit64\\dwagent.exe" : L"runtimepy3\\bit32\\dwagent.exe";
    if (!existsFile(runtimeExecutable)) {
        std::fwprintf(stderr, L"Extracted runtime executable is missing: %ls\n", runtimeExecutable.c_str());
        return 7;
    }
    std::wprintf(L"PASS: production extractor unpacked the installer and selected runtime; %ls exists.\n",
        runtimeExecutable.c_str());
    return 0;
}
