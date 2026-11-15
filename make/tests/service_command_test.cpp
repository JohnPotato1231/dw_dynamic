#include <iostream>

#define wmain service_entry_point_for_test
#include "../../os_win_service/src/main.cpp"
#undef wmain

int wmain(int argc, wchar_t** argv) {
    wchar_t executable[_MAX_PATH];
    GetModuleFileNameW(NULL, executable, _MAX_PATH);
    const std::wstring path(executable);
    if (path.substr(path.find_last_of(L'\\') + 1) != L"dwagsvc1.exe") {
        return 1;
    }
    const std::wstring quoted = L"\"" + path + L"\" ";
    if (getServiceCommand(L"run") != quoted + L"run" ||
        getServiceCommand(L"runonfly") != quoted + L"runonfly") {
        return 2;
    }
    std::wcout << L"PASS: renamed executable is used in both service registration commands." << std::endl;
    if (argc > 1) {
        const std::wstring fixture(argv[1]);
        if (getInstallSizeBytes(fixture) != 1025 || getInstallSizeKB(fixture) != 2) {
            return 3;
        }
        std::wcout << L"PASS: installed size includes nested files and rounds up to KiB." << std::endl;
    }
    return 0;
}
