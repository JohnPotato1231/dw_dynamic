// Exercise the actual service registration code without creating a service.
#include "../../os_win_service/src/main.h"

static std::wstring capturedName, capturedDisplay, capturedCommand;

static SC_HANDLE WINAPI fixtureOpenSCManager(LPCWSTR, LPCWSTR, DWORD) {
    return reinterpret_cast<SC_HANDLE>(1);
}
static BOOL WINAPI fixtureCloseServiceHandle(SC_HANDLE) { return TRUE; }
static SC_HANDLE WINAPI fixtureCreateService(SC_HANDLE, LPCWSTR name, LPCWSTR display,
        DWORD, DWORD, DWORD, DWORD, LPCWSTR command, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR) {
    capturedName = name;
    capturedDisplay = display;
    capturedCommand = command;
    return reinterpret_cast<SC_HANDLE>(2);
}

#undef OpenSCManager
#define OpenSCManager fixtureOpenSCManager
#define CloseServiceHandle fixtureCloseServiceHandle
#define CreateServiceW fixtureCreateService
#define wmain service_entry_point_for_identity_test
#include "../../os_win_service/src/main.cpp"
#undef wmain
#undef CreateServiceW
#undef CloseServiceHandle
#undef OpenSCManager

int wmain(int argc, wchar_t** argv) {
    wchar_t name[] = L"FixtureAgent";
    wchar_t command[] = L"\"C:\\Fixture\\fixture_service.exe\" run";
    serviceDisplayName = L"Fixture Remote Support";
    if (!installService(name, command) || capturedName != name ||
            capturedDisplay != serviceDisplayName || capturedCommand != command) return 1;
    serviceDisplayName.clear();
    if (!installService(name, command) || capturedDisplay != name) return 2;
    if (argc > 1) {
        workPath = argv[1];
        loadProperties();
        if (serviceName != L"ParserAgent" || serviceDisplayName != L"Parser Remote Support" ||
                pythonPath != L"C:\\Fixture\\runtime\\parser_agent.exe") return 3;
    }
    std::wcout << L"PASS: service registration keeps the internal name, display name and executable distinct; legacy defaults remain valid." << std::endl;
    return 0;
}
