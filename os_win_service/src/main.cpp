/*
This Source Code Form is subject to the terms of the Mozilla
Public License, v. 2.0. If a copy of the MPL was not distributed
with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
#include "main.h"

using namespace std;

GUID FIX_IID_IShellLinkW = {0x000214f9, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
GUID FIX_IID_IPersistFile = {0x0000010b, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
STARTUPINFOW siStartupInfo;
PROCESS_INFORMATION piProcessInfo;

bool bclose = false;
bool bRunning=false;
bool brunonfly=false;
wstring logfile = L"";
wstring serviceName = L"";
wstring serviceDisplayName = L"";
wstring publisherName = L"DWService";
wstring pidFileName = L"";
wstring startFileName = L"";
wstring stopFileName = L"";
wstring pythonHome = L"";
wstring pythonPath = L"";
wstring parameters = L"";
wstring workPath = L"";
wstring iconPath = L"";
wchar_t iconPathForLink[_MAX_PATH-1];


void WINAPI ServiceMain(DWORD argc, LPWSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD Opcode);

typedef bool (*FUPDATER)();
typedef void (*CallbackType)(const wchar_t*);
typedef bool (*FCALLBACKLOG)(CallbackType);

void trim(wstring& str, wchar_t c) {
    string::size_type pos = str.find_last_not_of(c);
    if (pos != string::npos) {
        str.erase(pos + 1);
        pos = str.find_first_not_of(c);
        if (pos != string::npos) str.erase(0, pos);
    } else str.erase(str.begin(), str.end());
}

void trimAll(wstring& str) {
    trim(str, ' ');
    trim(str, '\r');
    trim(str, '\n');
    trim(str, '\t');
}

wchar_t* towchar_t(wstring& str) {
    wchar_t* apps = new wchar_t[str.size() + 1];
	wcscpy(apps, str.c_str());
	apps[str.size()]='\0';
    return apps;
}

void WriteToLog(const wchar_t* str) {
    if (logfile.compare(L"") != 0) {
    	HANDLE hFile = CreateFileW(logfile.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    	if (hFile!=INVALID_HANDLE_VALUE){
    		DWORD dwBytesWritten;
    		time_t t = time(NULL);
			struct tm *tlc = localtime(&t);
			wchar_t* stm = _wasctime(tlc);
			stm[wcslen(stm)-1] = '\0';
			wstring apps = L"";
			apps.append(stm);
			apps.append(L" ");
			apps.append(str);
			apps.append(L"\n");
			int numc = WideCharToMultiByte(CP_UTF8, 0, apps.c_str(), apps.length(), NULL, 0, NULL, NULL);
			if (numc){
				char *szTo = new char[numc + 1];
				szTo[numc] = '\0';
				WideCharToMultiByte(CP_UTF8, 0, apps.c_str(), -1, szTo, numc, NULL, NULL);
				WriteFile(hFile, szTo, numc, &dwBytesWritten, NULL);
				delete[] szTo;
			}
			CloseHandle(hFile);
    	}
    }
}

bool existsFile(wstring fileName) {
	return GetFileAttributesW(fileName.c_str())!=INVALID_FILE_ATTRIBUTES;
}

bool existsDir(wstring file){
	DWORD returnvalue;
	returnvalue = GetFileAttributesW(file.c_str());
	if(returnvalue == INVALID_FILE_ATTRIBUTES){
		return false;
	}else{
		return true;
	}
}

bool existsFileInWorkDir(wstring fileName) {
	wstring path = workPath;
	path.append(L"\\").append(fileName);
    if (existsFile(path)){
		return true;
	}else{
		return false;
	}
}

BOOL removeFileInWorkDir(wstring fileName) {
    wstring path = workPath;
	path.append(L"\\").append(fileName);
    return DeleteFileW(towchar_t(path)) == 0;
}

BOOL makeFileInWorkDir(wstring fileName) {
    wstring path = workPath;
	path.append(L"\\").append(fileName);
    FILE* f = _wfopen(towchar_t(path), L"w+");
    if (f == NULL)
        return false;
    fclose(f);
    return true;
}

BOOL removePidFile() {
    wstring path = workPath;
	path.append(L"\\").append(pidFileName);
    return DeleteFileW(towchar_t(path)) == 0;
}

BOOL makePidFile() {
	removePidFile();

	DWORD wpid = GetCurrentProcessId();
	wstring path = workPath;
	path.append(L"\\").append(pidFileName);
    FILE* f = _wfopen(towchar_t(path), L"w+");
    if (f == NULL){
        return false;
    }
	fwprintf(f, L"%d", wpid);
    fclose(f);
    return true;
}

void processKill() {
    TerminateProcess(piProcessInfo.hProcess, 0);
    removeFileInWorkDir(startFileName);
    removeFileInWorkDir(stopFileName);
}

bool processIsActive() {
	DWORD code;
	if (GetExitCodeProcess(piProcessInfo.hProcess, &code)) {
		if (code == STILL_ACTIVE) {
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
}

bool checkUpdate() {
	try{
		wstring fupd=workPath;
		fupd.append(L"\\native\\dwagupd.dll");
		HINSTANCE hinstLib = LoadLibraryW(fupd.c_str());
		if (hinstLib != NULL){
			FCALLBACKLOG FClbk = (FCALLBACKLOG)GetProcAddress(hinstLib, "setCallbackWriteLog");
			if (FClbk!= NULL){
				FClbk(WriteToLog);
			}else{
				WriteToLog(L"ERROR: Updater method setCallbackWriteLog not loaded.");
			}
			FUPDATER FUpd = (FUPDATER) GetProcAddress(hinstLib, "checkUpdate");
			if (FUpd!= NULL){
				bool bret = FUpd();
				if (!FreeLibrary(hinstLib)){
					WriteToLog(L"ERROR: Updater function not unloaded.");
				}
				return bret;
			}else{
				WriteToLog(L"ERROR: Updater method checkUpdate not loaded.");
			}
		}else{
			WriteToLog(L"ERROR: Updater library not loaded.");
		}
	} catch (...) {
		WriteToLog(L"ERROR: Updater library.");
	}
	return false;
}

bool processStart() {
    bool result = false;

	if (!brunonfly){
		if (existsFileInWorkDir(startFileName)) {
			WriteToLog(L"WARNING: Removed start file.");
			removeFileInWorkDir(startFileName);
		}

		if (existsFileInWorkDir(stopFileName)) {
			WriteToLog(L"WARNING: Removed stop file.");
			removeFileInWorkDir(stopFileName);
		}
	}


	wstring args = L"\"";
	args.append(pythonPath);
	args.append(L"\" ").append(parameters);
	wstring apps=L"WorkPath=";
	WriteToLog(apps.append(workPath).c_str());
	apps=L"Command=";
    WriteToLog(apps.append(args).c_str());

    memset(&siStartupInfo, 0, sizeof (siStartupInfo));
    memset(&piProcessInfo, 0, sizeof (piProcessInfo));
    siStartupInfo.cb = sizeof (siStartupInfo);
    siStartupInfo.lpReserved=NULL;
    siStartupInfo.lpDesktop=NULL;
    wstring titName;
    titName.append(serviceName);
    titName.append(L"Svc");
    siStartupInfo.lpTitle=(LPWSTR)titName.c_str();
	siStartupInfo.dwX=0;
    siStartupInfo.dwY=0;
    siStartupInfo.dwXSize=0;
    siStartupInfo.dwYSize=0;
    siStartupInfo.dwXCountChars=0;
    siStartupInfo.dwYCountChars=0;
    siStartupInfo.dwFillAttribute=0;
	siStartupInfo.wShowWindow = SW_HIDE;
	siStartupInfo.dwFlags = STARTF_USESHOWWINDOW;

	SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;

	if (pythonHome.compare(L"") != 0) {
		if (SetEnvironmentVariableW(L"PYTHONHOME",pythonHome.c_str())){
			wstring appph=L"";
			appph.append(L"Set PYTHONHOME=");
			appph.append(pythonHome);
			WriteToLog(appph.c_str());
		}
	}

	if (CreateProcessW(NULL, 
            towchar_t(args),
            NULL,
            NULL,
            sa.bInheritHandle,
            HIGH_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, 
			NULL,
            towchar_t(workPath), 
            &siStartupInfo,
            &piProcessInfo) == TRUE) {

		if (!brunonfly){
			//Attende la creazione del file .start
			int cnt = 0;
			while ((cnt <= 20) && (processIsActive()) && (!existsFileInWorkDir(startFileName))) {
				Sleep(2000);
				cnt++;
			}

			if ((processIsActive()) && (existsFileInWorkDir(startFileName))) {
				removeFileInWorkDir(startFileName);
				result = true;
			} else {
				if (!processIsActive()){
					WriteToLog(L"ERROR: Process not Active.");
				}else if (!existsFileInWorkDir(startFileName)){
					WriteToLog(L"ERROR: Missing start file.");
				}
				processKill();
			}
		}else{
			result = true;
		}
    }else{
		wchar_t strmsg[1000];
		wchar_t strerr[10];
		wcscpy(strmsg, L"CreateProcess failed (error:");
		_itow(GetLastError(),strerr,10);
		wcscat(strmsg, strerr);
		wcscat(strmsg, L").");
		WriteToLog(strmsg);
	}
    return result;
}

void processStop() {
    ServiceStatus.dwWin32ExitCode = 0;
	//Attende l'eliminazione del file .stop
    makeFileInWorkDir(stopFileName);
    int cnt = 0;
    while ((cnt <= 20) && (processIsActive())) {
        Sleep(2000);
        cnt++;
    }
    if (processIsActive()) {
        ServiceStatus.dwWin32ExitCode = 1;
        processKill();
    }
    removeFileInWorkDir(stopFileName);


}

void loadProperties() {
	wstring appfn = workPath;
	appfn.append(L"\\native\\service.properties");
	WriteToLog(L"Reading properties...");
	WriteToLog(appfn.c_str());

	HANDLE hFile = CreateFileW(appfn.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile!=INVALID_HANDLE_VALUE){
		DWORD  dwBytesRead;
		char buff[16*1024];
		ReadFile(hFile, buff, sizeof(buff), &dwBytesRead, NULL);
		CloseHandle(hFile);


		wstring apps;
		int numc = MultiByteToWideChar(CP_UTF8, 0, buff, dwBytesRead, NULL, 0);
		if (numc){
			wchar_t *wszTo = new wchar_t[numc + 1];
			wszTo[numc] = L'\0';
			MultiByteToWideChar(CP_UTF8, 0, buff, dwBytesRead, wszTo, numc);
			apps = wszTo;
			delete[] wszTo;
		}

		//WriteToLog(L"***********************");
		//WriteToLog(apps.c_str());

		int pel = 0;
		while(pel>=0){
			int prepel=pel;
			pel = apps.find(L"\n",prepel);
			wstring line;
			if (pel<0){
				line = apps.substr(prepel);
			}else{
				line = apps.substr(prepel, pel-prepel);
				pel++;
			}
			trimAll(line);

			//Legge le proprietà necessarie
			int endpart1 = line.find_first_of(L"=");
			wstring part1 = line.substr(0, endpart1);
			trimAll(part1);
			wstring part2 = line.substr(endpart1 + 1);
			trimAll(part2);

			if (part1.compare(L"serviceName") == 0) {
				serviceName = part2;
				pidFileName = L"dwagent.pid";
				startFileName = L"dwagent.start";
				stopFileName = L"dwagent.stop";
			}

			if (part1.compare(L"serviceDisplayName") == 0) {
				serviceDisplayName = part2;
			}
			if (part1.compare(L"publisher") == 0) {
				publisherName = part2.empty() ? L"DWService" : part2;
			}
			if (part1.compare(L"iconPath") == 0) {
				iconPath = part2;
			}

			if (part1.compare(L"pythonPath") == 0) {
				pythonPath = part2;
			}

			if (part1.compare(L"pythonHome") == 0) {
				pythonHome = part2;
			}

			if (part1.compare(L"workPath") == 0) {
				workPath = part2;
			}

			if (part1.compare(L"parameters") == 0) {
				parameters = part2;
			}
		}


	}else{
		throw "ERROR: Read properties error.";
	}
    WriteToLog(L"Readed properties.");
}


wstring getDWAgentPath(){
	wchar_t strPathName[_MAX_PATH];
	GetModuleFileNameW(NULL, strPathName, _MAX_PATH);
	wstring newPath(strPathName);
	int fpos = newPath.find_last_of('\\');
	if (fpos != -1)
		newPath = newPath.substr(0,(fpos));
	fpos = newPath.find_last_of('\\');
	if (fpos != -1)
		newPath = newPath.substr(0,(fpos));
	return newPath;
}

wstring getServiceCommand(const wchar_t *mode){
	wchar_t executable[_MAX_PATH];
	DWORD length = GetModuleFileNameW(NULL, executable, _MAX_PATH);
	if (length == 0 || length >= _MAX_PATH){
		throw "ERROR: Cannot determine service executable path.";
	}
	return L"\"" + wstring(executable, length) + L"\" " + mode;
}

//######################################
//############ INSTALLER ###############
//######################################

vector<wstring> split(const wstring& s, const wstring& delim, const bool keep_empty = true) {
    vector<wstring> result;
    if (delim.empty()) {
        result.push_back(s);
        return result;
    }
    wstring::const_iterator substart = s.begin(), subend;
    while (true) {
        subend = search(substart, s.end(), delim.begin(), delim.end());
        wstring temp(substart, subend);
        if (keep_empty || !temp.empty()) {
            result.push_back(temp);
        }
        if (subend == s.end()) {
            break;
        }
        substart = subend + delim.size();
    }
    return result;
}

void createLink(wchar_t* workPath,wchar_t* dstpath,wchar_t *command, wchar_t *label){
	//Crea Directory
	CoInitialize(NULL);
	
	//Crea Link
    IShellLinkW* pShellLink;
    IPersistFile* pPersistFile;

    HRESULT hres = CoCreateInstance(CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,
                                                        FIX_IID_IShellLinkW,
                                                        reinterpret_cast<void**>(&pShellLink));
     if (SUCCEEDED(hres)){
		wchar_t szExePath[_MAX_PATH-1];
		wcscpy(szExePath, workPath);
		wcscat(szExePath, L"\\native\\dwaglnc.exe");
		pShellLink->SetPath(szExePath);

		wchar_t szExeArg[_MAX_PATH-1];
		wcscpy(szExeArg, command);
		pShellLink->SetArguments(szExeArg);

		wchar_t szWorkPath[_MAX_PATH-1];
		wcscpy(szWorkPath, workPath);
		wcscat(szWorkPath, L"\\native");
		pShellLink->SetWorkingDirectory(szWorkPath);
		pShellLink->SetIconLocation(iconPathForLink,0);

        hres = pShellLink->QueryInterface(FIX_IID_IPersistFile, reinterpret_cast<void**>(&pPersistFile));

        if (SUCCEEDED(hres)){
			wchar_t WideCharacterBuffer[_MAX_PATH-1];
			wcscpy(WideCharacterBuffer, dstpath);
			wcscat(WideCharacterBuffer, L"\\");
			wcscat(WideCharacterBuffer, label);
			wcscat(WideCharacterBuffer, L".lnk" );
			hres = pPersistFile->Save(WideCharacterBuffer, TRUE);
			pPersistFile->Release();
        }
        pShellLink->Release();
    }
}

ULONGLONG getInstallSizeBytes(const wstring& directory){
	WIN32_FIND_DATAW entry;
	HANDLE search = FindFirstFileW((directory + L"\\*").c_str(), &entry);
	if (search == INVALID_HANDLE_VALUE){
		return 0;
	}
	ULONGLONG total = 0;
	do {
		if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0
				|| (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)){
			continue;
		}
		if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
			total += getInstallSizeBytes(directory + L"\\" + entry.cFileName);
		}else{
			total += (static_cast<ULONGLONG>(entry.nFileSizeHigh) << 32) | entry.nFileSizeLow;
		}
	} while (FindNextFileW(search, &entry));
	FindClose(search);
	return total;
}

DWORD getInstallSizeKB(const wstring& directory){
	// Control Panel expects EstimatedSize in KiB, rounded up.
	ULONGLONG bytes = getInstallSizeBytes(directory);
	ULONGLONG kilobytes = bytes / 1024 + (bytes % 1024 != 0);
	return static_cast<DWORD>(kilobytes > MAXDWORD ? MAXDWORD : kilobytes);
}

bool installShortcuts(wchar_t* workPath){
	//Crea i link nello start menu
	LPITEMIDLIST pidl;
	HRESULT hr = SHGetSpecialFolderLocation(NULL, CSIDL_COMMON_PROGRAMS, &pidl);
	if (hr==S_OK){
		wchar_t SpecialFolderPath[_MAX_PATH-1];
		SHGetPathFromIDListW(pidl, SpecialFolderPath);
		LPMALLOC pMalloc;
		hr = SHGetMalloc(&pMalloc);
		pMalloc->Free(pidl);
		pMalloc->Release();

		wchar_t myDirectory[_MAX_PATH-1];
		wcscpy(myDirectory, SpecialFolderPath);
		wcscat(myDirectory,L"\\");
		wcscat(myDirectory, towchar_t(serviceName));
		CreateDirectoryW(myDirectory, NULL);
		createLink(workPath,myDirectory, (wchar_t*)L"monitor", towchar_t(serviceName));

		//Crea link in Native
		wchar_t appDirectory[_MAX_PATH-1];
		wcscpy(appDirectory, workPath);
		wcscat(appDirectory,L"\\");
		wcscat(appDirectory, L"native");
		createLink(workPath, appDirectory, (wchar_t*)L"monitor", towchar_t(serviceName));
		createLink(workPath, appDirectory, (wchar_t*)L"configure", (wchar_t*)L"Configure");
		createLink(workPath, appDirectory, (wchar_t*)L"uninstall", (wchar_t*)L"Uninstall");
	}
	
	//Crea la voce di registo per l'uninstaller
	HKEY regkey;
	wstring unpth=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	unpth.append(serviceName);
	LSTATUS st = RegCreateKeyW(HKEY_LOCAL_MACHINE,towchar_t(unpth), &regkey);
	if (st==ERROR_SUCCESS){

		wchar_t* appdn = towchar_t(serviceDisplayName.empty() ? serviceName : serviceDisplayName);
		st = RegSetValueExW(regkey, L"DisplayName",0, REG_SZ, (BYTE *)appdn, wcslen(appdn)*2);
		st = RegSetValueExW(regkey, L"DisplayIcon",0, REG_SZ, (BYTE *)iconPathForLink, wcslen(iconPathForLink)*2);
		st = RegSetValueExW(regkey, L"InstallLocation",0, REG_SZ, (BYTE *)workPath, wcslen(workPath)*2);
		const wchar_t* publisher = publisherName.c_str();
		RegSetValueExW(regkey, L"Publisher", 0, REG_SZ,
			reinterpret_cast<const BYTE*>(publisher),
			static_cast<DWORD>((publisherName.size() + 1) * sizeof(wchar_t)));
		const wchar_t version[] = L"4.8.1907.16384";
		st = RegSetValueExW(regkey, L"DisplayVersion", 0, REG_SZ,
			reinterpret_cast<const BYTE*>(version), sizeof(version));
		DWORD estimatedSize = getInstallSizeKB(workPath);
		st = RegSetValueExW(regkey, L"EstimatedSize", 0, REG_DWORD,
			reinterpret_cast<const BYTE*>(&estimatedSize), sizeof(estimatedSize));
		wstring path=L"";
		path.append(L"\"").append(workPath).append(L"\\native\\dwaglnc.exe\" uninstall");
		wchar_t* appun = towchar_t(path);
		st = RegSetValueExW(regkey, L"UninstallString",0, REG_SZ, (BYTE *)appun, wcslen(appun)*2);

		RegCloseKey(regkey);
	}
	return true;
}

bool missingInstallObject(DWORD error){
	return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

bool commonInstallFolder(int folder, wstring& path){
	LPITEMIDLIST pidl = NULL;
	HRESULT result = SHGetSpecialFolderLocation(NULL, folder, &pidl);
	if (FAILED(result)){
		SetLastError(HRESULT_CODE(result) ? HRESULT_CODE(result) : ERROR_PATH_NOT_FOUND);
		return false;
	}
	wchar_t directory[MAX_PATH];
	BOOL found = SHGetPathFromIDListW(pidl, directory);
	CoTaskMemFree(pidl);
	if (!found){
		SetLastError(ERROR_PATH_NOT_FOUND);
		return false;
	}
	path = directory;
	return true;
}

bool removeOptionalInstallFile(const wstring& path){
	return DeleteFileW(path.c_str()) || missingInstallObject(GetLastError());
}

bool removeShortcuts(){
	// Only remove this installation's link and empty folder, never other files.
	DWORD error = ERROR_SUCCESS;
	wstring programs;
	if (commonInstallFolder(CSIDL_COMMON_PROGRAMS, programs)){
		wstring directory = programs + L"\\" + serviceName;
		if (!removeOptionalInstallFile(directory + L"\\" + serviceName + L".lnk")){
			error = GetLastError();
		}
		if (!RemoveDirectoryW(directory.c_str())){
			DWORD directoryError = GetLastError();
			// Other files in the Start menu folder belong to the user; retain them.
			if (!missingInstallObject(directoryError) && directoryError != ERROR_DIR_NOT_EMPTY
					&& error == ERROR_SUCCESS) error = directoryError;
		}
	}else{
		error = GetLastError();
	}
	// Some older registrations contain subkeys. RegDeleteKey cannot remove them.
	LSTATUS status = RegDeleteTreeW(HKEY_LOCAL_MACHINE,
		(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + serviceName).c_str());
	if (status != ERROR_SUCCESS && !missingInstallObject(status) && error == ERROR_SUCCESS) error = status;
	SetLastError(error);
	return error == ERROR_SUCCESS;
}

bool installAutoRun(wchar_t* name, wchar_t* workPath){
	wstring app = L"\"";
	app.append(workPath);
	app.append(L"\\native\\dwaglnc.exe\" systray");	
	wchar_t* cmd = towchar_t(app);

	HKEY regkey;
	LSTATUS st = RegOpenKeyW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &regkey);
	if (st==ERROR_SUCCESS){
		st = RegSetValueExW(regkey, name,0, REG_SZ, (BYTE *)cmd, wcslen(cmd)*2);
		RegCloseKey(regkey);
	}
	if (st!=ERROR_SUCCESS){
		LPITEMIDLIST pidl;
		HRESULT hr = SHGetSpecialFolderLocation(NULL, CSIDL_COMMON_STARTUP, &pidl);
		if (hr==S_OK){
			wchar_t SpecialFolderPath[_MAX_PATH-1];
			SHGetPathFromIDListW(pidl, SpecialFolderPath);
			LPMALLOC pMalloc;
			hr = SHGetMalloc(&pMalloc);
			pMalloc->Free(pidl);
			pMalloc->Release();

			wchar_t appDirectory[_MAX_PATH-1];
			wcscpy(appDirectory, SpecialFolderPath);
			createLink(workPath, appDirectory, (wchar_t*)L"systray", towchar_t(serviceName));
		}
	}
	return true;

}

bool removeAutoRun(wchar_t* name){
	DWORD error = ERROR_SUCCESS;
	HKEY regkey;
	LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &regkey);
	if (status == ERROR_SUCCESS){
		status = RegDeleteValueW(regkey, name);
		RegCloseKey(regkey);
	}
	if (status != ERROR_SUCCESS && !missingInstallObject(status)) error = status;
	// Older installations may have used the startup link fallback. Remove both.
	wstring startup;
	if (commonInstallFolder(CSIDL_COMMON_STARTUP, startup)){
		if (!removeOptionalInstallFile(startup + L"\\" + serviceName + L".lnk") && error == ERROR_SUCCESS){
			error = GetLastError();
		}
	}else if (error == ERROR_SUCCESS){
		error = GetLastError();
	}
	SetLastError(error);
	return error == ERROR_SUCCESS;
}

bool checkStateService(SC_HANDLE schService,DWORD state){
	SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    BOOL bok = QueryServiceStatusEx(
            schService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE) & ssp,
            sizeof (SERVICE_STATUS_PROCESS),
            &dwBytesNeeded);
    if (bok) {
        if (ssp.dwCurrentState == state) {
            return true;
        }
    }
    return false;
}

bool waitStateService(SC_HANDLE schService,DWORD state){
	int cnt = 0;
    while (cnt <= 30) {
        Sleep(2000);
        SERVICE_STATUS_PROCESS ssp;
        DWORD dwBytesNeeded;
        BOOL bok = QueryServiceStatusEx(
                schService,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE) & ssp,
                sizeof (SERVICE_STATUS_PROCESS),
                &dwBytesNeeded);
        if (bok) {
            if (ssp.dwCurrentState == state) {
                return true;
            }
        } else {
            return false;
        }
        cnt++;
    }
    return false;
}

bool startService(wchar_t* serviceName) {
	bool bret=false;
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (schSCManager){
		SC_HANDLE schService = OpenServiceW(schSCManager, serviceName, SERVICE_START | SERVICE_QUERY_STATUS |  SERVICE_ENUMERATE_DEPENDENTS);
		if (schService){
			if (checkStateService(schService, SERVICE_STOPPED)){
				BOOL bok = StartService(schService, 0, NULL);
				if (bok) {
					bret = waitStateService(schService, SERVICE_RUNNING);
				}
			}
			CloseServiceHandle(schService);
		}
		CloseServiceHandle(schSCManager);
	}
	return bret;
}

bool waitServiceAbsent(SC_HANDLE manager, const wchar_t* name, DWORD timeout){
	DWORD started = GetTickCount();
	for (;;){
		SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS);
		if (service){
			CloseServiceHandle(service);
		}else{
			DWORD error = GetLastError();
			if (error == ERROR_SERVICE_DOES_NOT_EXIST){
				SetLastError(ERROR_SUCCESS);
				return true;
			}
			if (error != ERROR_SERVICE_MARKED_FOR_DELETE) return false;
		}
		DWORD elapsed = GetTickCount() - started;
		if (elapsed >= timeout){
			SetLastError(ERROR_TIMEOUT);
			return false;
		}
		Sleep(min(static_cast<DWORD>(250), timeout - elapsed));
	}
}

bool stopService(wchar_t* serviceName) {
	SC_HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!manager) return false;
	SC_HANDLE service = OpenServiceW(manager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
	bool result = false;
	DWORD error = ERROR_SUCCESS;
	if (!service){
		error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST) result = true;
		else if (error == ERROR_SERVICE_MARKED_FOR_DELETE) result = waitServiceAbsent(manager, serviceName, 60000);
		if (!result) error = GetLastError();
	}else{
		DWORD started = GetTickCount();
		bool requested = false;
		for (;;){
			SERVICE_STATUS_PROCESS status = {};
			DWORD needed;
			if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
					reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)){
				error = GetLastError();
				break;
			}
			if (status.dwCurrentState == SERVICE_STOPPED){
				result = true;
				break;
			}
			if (!requested && (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_PAUSED)){
				SERVICE_STATUS stopped = {};
				if (ControlService(service, SERVICE_CONTROL_STOP, &stopped)){
					requested = true;
				}else{
					error = GetLastError();
					if (error == ERROR_SERVICE_NOT_ACTIVE){
						result = true;
						break;
					}
					// Another stop or startup transition may have won the race.
					if (error != ERROR_SERVICE_CANNOT_ACCEPT_CTRL) break;
				}
			}
			DWORD elapsed = GetTickCount() - started;
			if (elapsed >= 60000){
				error = ERROR_TIMEOUT;
				break;
			}
			DWORD interval = max(static_cast<DWORD>(100), min(static_cast<DWORD>(1000), status.dwWaitHint / 10));
			Sleep(min(interval, static_cast<DWORD>(60000) - elapsed));
		}
		CloseServiceHandle(service);
	}
	CloseServiceHandle(manager);
	SetLastError(result ? ERROR_SUCCESS : error);
	return result;
}

bool installService(wchar_t* serviceName, wchar_t* cmd) {
	bool bret=false;
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager){
		SC_HANDLE schService = CreateServiceW(
				schSCManager,
				serviceName,
				serviceDisplayName.empty() ? serviceName : serviceDisplayName.c_str(),
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_NORMAL,
				cmd,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL);
		if (schService != NULL) {
			bret = true;
			CloseServiceHandle(schService);
		}		
		CloseServiceHandle(schSCManager);
	}
    return bret;
}

bool deleteService(wchar_t* serviceName) {
	SC_HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!manager) return false;
	SC_HANDLE service = OpenServiceW(manager, serviceName, DELETE);
	bool result = false;
	bool pending = false;
	DWORD error = ERROR_SUCCESS;
	if (service){
		pending = DeleteService(service) != FALSE;
		if (!pending){
			error = GetLastError();
			pending = error == ERROR_SERVICE_MARKED_FOR_DELETE;
		}
		// Windows cannot finish deletion while this handle remains open.
		CloseServiceHandle(service);
	}else{
		error = GetLastError();
		result = error == ERROR_SERVICE_DOES_NOT_EXIST;
		pending = error == ERROR_SERVICE_MARKED_FOR_DELETE;
	}
	if (pending){
		result = waitServiceAbsent(manager, serviceName, 60000);
		if (!result) error = GetLastError();
	}
	CloseServiceHandle(manager);
	SetLastError(result ? ERROR_SUCCESS : error);
	return result;
}

bool startRunOnFly(wchar_t* serviceName) {
	bool bret=false;
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager){
		//Elimina vecchio servizia (Se esiste)
		SC_HANDLE schService = OpenServiceW(schSCManager, serviceName, SC_MANAGER_ALL_ACCESS);
		if (schService != NULL) {
			SERVICE_STATUS ssStatus;
			ControlService(schService, SERVICE_CONTROL_STOP, &ssStatus);
			DeleteService(schService);
		}
		CloseServiceHandle(schService);		
		//Crea Servizio
		wstring cmd = getServiceCommand(L"runonfly");
		schService = CreateServiceW(
				schSCManager,
				serviceName,
				serviceName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS,
				SERVICE_DEMAND_START,
				SERVICE_ERROR_NORMAL,
				cmd.c_str(),
				NULL,
				NULL,
				NULL,
				NULL,
				NULL);
		if (schService != NULL) {
			SERVICE_STATUS ssStatus;
			BOOL bok = StartService(schService, 0, NULL);
			if (bok) {
				bret = true;
			}
			ControlService(schService, SERVICE_CONTROL_STOP, &ssStatus);
			DeleteService(schService);
			CloseServiceHandle(schService);
		}
		CloseServiceHandle(schSCManager);
	}
	return bret;
}

void setIconPathForLink(wchar_t* workPath){
	if (iconPath.compare(L"") == 0) {
		wcscpy(iconPathForLink, workPath);
		wcscat(iconPathForLink, L"\\ui\\images\\logo.ico");
	}else{
		wcscpy(iconPathForLink, iconPath.c_str());
	}
}

int wmain(int argc, wchar_t **argv) {
	if (argc<2){
		printf("ERROR: Unknown command");
		return 0;
	}
	wstring command = wstring(argv[1]);
    workPath = getDWAgentPath();
    if ((command.compare(L"run") == 0) || (command.compare(L"runonfly") == 0)){
        logfile = workPath;
		logfile.append(L"\\native\\service.log");
        //DeleteFileW(towchar_t(logfile));
    }
    try {
        loadProperties();
        if (command.compare(L"run") == 0) {
			SERVICE_TABLE_ENTRYW ServiceTable[]={{towchar_t(serviceName),ServiceMain},{NULL,NULL}};
			StartServiceCtrlDispatcherW(ServiceTable);
		} else if (command.compare(L"runonfly") == 0) {
			brunonfly=true;
			SERVICE_TABLE_ENTRYW ServiceTable[]={{towchar_t(serviceName),ServiceMain},{NULL,NULL}};
			StartServiceCtrlDispatcherW(ServiceTable);
		} else if (command.compare(L"startRunOnFly") == 0) {
			if (startRunOnFly(towchar_t(serviceName))){
				printf("OK");
			}else{
				printf("ERROR");
			}			
		} else if (command.compare(L"installService") == 0) {
			wstring app = getServiceCommand(L"run");
			if (installService(towchar_t(serviceName), towchar_t(app))){
				printf("OK");
			}else{
				printf("ERROR");
			}
		} else if (command.compare(L"deleteService") == 0) {
			if (deleteService(towchar_t(serviceName))){
				printf("OK");
			}else{
				printf("ERROR: Windows error %lu", static_cast<unsigned long>(GetLastError()));
			}
		} else if (command.compare(L"startService") == 0) {
			if (startService(towchar_t(serviceName))){
				printf("OK");
			}else{
				printf("ERROR");
			}
		} else if (command.compare(L"stopService") == 0) {
			if (stopService(towchar_t(serviceName))){
				printf("OK");
			}else{
				printf("ERROR: Windows error %lu", static_cast<unsigned long>(GetLastError()));
			}
		} else if (command.compare(L"installShortcuts") == 0) {
			setIconPathForLink(towchar_t(workPath));
			if (installShortcuts(towchar_t(workPath))){
				printf("OK");
			}else{
				printf("ERROR");
			}			
		} else if (command.compare(L"removeShortcuts") == 0) {
			if (removeShortcuts()){
				printf("OK");
			}else{
				printf("ERROR: Windows error %lu", static_cast<unsigned long>(GetLastError()));
			}
		} else if (command.compare(L"installAutoRun") == 0) {
			setIconPathForLink(towchar_t(workPath));
			wstring monname;
			monname.append(serviceName);
			monname.append(L"Mon");
			if (installAutoRun(towchar_t(monname), towchar_t(workPath))){
				printf("OK");
			}else{
				printf("ERROR");
			}
		} else if (command.compare(L"removeAutoRun") == 0) {
			wstring monname;
			monname.append(serviceName);
			monname.append(L"Mon");
			if (removeAutoRun(towchar_t(monname))){
				printf("OK");
			}else{
				printf("ERROR: Windows error %lu", static_cast<unsigned long>(GetLastError()));
			}
		} else {
            printf("ERROR: Unknown command");
        }
    } catch (...) {
        if ((command.compare(L"run") == 0) || (command.compare(L"runonfly") == 0)){
            WriteToLog(L"ERROR: Unexpected");
        } else {
            printf("ERROR: Unexpected");
        }
        return 1;
    }	
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv){
    if (!brunonfly){
		WriteToLog(L"Service starting...");
		makePidFile();
	}

	ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    hStatus = RegisterServiceCtrlHandlerW(towchar_t(serviceName),(LPHANDLER_FUNCTION) ServiceCtrlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE) 0) {
        return;
    }

	if (brunonfly){ //Gli aggiornamenti li fa l'installer
		if (processStart()){
			ServiceStatus.dwCurrentState = SERVICE_RUNNING;
			ServiceStatus.dwCheckPoint = 0;
			ServiceStatus.dwWaitHint = 0;
			SetServiceStatus(hStatus, &ServiceStatus);
			WriteToLog(L"process created.");
			ServiceStatus.dwWin32ExitCode = 0;
		}else{
			WriteToLog(L"process creating error.");
		}
	}else{
		for (int ti=1;ti<=3;ti++){//3 tentativi
			if (processStart()){
				ServiceStatus.dwCurrentState = SERVICE_RUNNING;
				ServiceStatus.dwCheckPoint = 0;
				ServiceStatus.dwWaitHint = 0;
				SetServiceStatus(hStatus, &ServiceStatus);
				WriteToLog(L"Service started.");
				bRunning=true;
				while(bRunning)	{
					if (!processIsActive()){
						WriteToLog(L"Check updating...");
						if (checkUpdate()){
							WriteToLog(L"updated.");
							WriteToLog(L"Process creating...");
							if (processStart()){
								WriteToLog(L"Process created.");
							}else{
								WriteToLog(L"Process creating error.");
							}
						}else{
							WriteToLog(L"Update error.");
						}
					}
					for (int i=1;i<=5;i++){
						if (bRunning){
							Sleep(1000);
						}
					}
				}
				WriteToLog(L"Service stopping...");
				processStop();
				break;
			}else{
				WriteToLog(L"Process creating error.");
				Sleep(3000);
			}
		}
	}
	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
	
	if (!brunonfly){
		removePidFile();
		WriteToLog(L"Service stopped.");
	}
	return;
}

void WINAPI ServiceCtrlHandler(DWORD Opcode){
    switch (Opcode) {
        case SERVICE_CONTROL_STOP:
            bRunning=false;
			//Wait
			while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
				Sleep(100);
			}
			break;
        case SERVICE_CONTROL_SHUTDOWN:
            bRunning=false;
			//Wait
			while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
				Sleep(100);
			}
			break;

        default:
            break;
    }
    return;
}

