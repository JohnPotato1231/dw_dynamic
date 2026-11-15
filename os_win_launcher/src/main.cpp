/*
This Source Code Form is subject to the terms of the Mozilla
Public License, v. 2.0. If a copy of the MPL was not distributed
with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "main.h"

using namespace std;

wstring pythonPath = L"";

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

BOOL isRunAsAdmin(){
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)){
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    if (pAdministratorsGroup){
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }
    if (ERROR_SUCCESS != dwError){
        throw dwError;
    }
    return fIsRunAsAdmin;
}

bool existsFile(wstring fileName) {
	return GetFileAttributesW(fileName.c_str())!=INVALID_FILE_ATTRIBUTES;
}


bool deleteDir(const wchar_t *path, bool preserveOwner = false, bool* ownerRemoved = NULL){
	bool bret=true;
    WIN32_FIND_DATAW FindFileData;
    HANDLE hFind;
    DWORD Attributes;
    wchar_t str[MAX_PATH];
	wcscpy(str,path);
	wcscat(str,L"\\*.*");
    hFind = FindFirstFileW(str, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE){
        return GetLastError() == ERROR_FILE_NOT_FOUND && RemoveDirectoryW(path);
    }
    do{
        if (wcscmp(FindFileData.cFileName, L".") != 0 && wcscmp(FindFileData.cFileName, L"..") != 0)
        {
            // Keep the generation marker until all other files can be removed.
            if (preserveOwner && wcscmp(FindFileData.cFileName, L"setup-owner.json") == 0) continue;
            wcscpy(str, path);
            wcscat(str,L"\\");
            wcscat (str,FindFileData.cFileName);
            Attributes = GetFileAttributesW(str);
			if (Attributes & FILE_ATTRIBUTE_REPARSE_POINT){
                if (Attributes & FILE_ATTRIBUTE_DIRECTORY){
                    if (!RemoveDirectoryW(str)) bret=false;
                }else{
                    if (!DeleteFileW(str)) bret=false;
                }
            }else if (Attributes & FILE_ATTRIBUTE_DIRECTORY){
                if (!deleteDir(str)){
					bret=false;
					break;
				}
            }else{
				if (!DeleteFileW(str)){
					bret=false;
					break;
				}
            }
        }
    }while(FindNextFileW(hFind, &FindFileData));
    FindClose(hFind);
    if (bret && preserveOwner){
        wstring owner = wstring(path) + L"\\setup-owner.json";
        if (DeleteFileW(owner.c_str())){
            if (ownerRemoved) *ownerRemoved = true;
        }else{
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) bret=false;
        }
    }
    if (!bret) return false;
    return RemoveDirectoryW(path) && bret;
}

bool startRemove(wstring dwPath){
	wchar_t temporary[MAX_PATH], unique[MAX_PATH];
	DWORD length = GetTempPathW(MAX_PATH, temporary);
	if (!length || length >= MAX_PATH){
		if (length >= MAX_PATH) SetLastError(ERROR_FILENAME_EXCED_RANGE);
		return false;
	}
	if (!GetTempFileNameW(temporary, L"DWR", 0, unique)) return false;
	if (!DeleteFileW(unique) || !CreateDirectoryW(unique, NULL)) return false;
	wstring directory(unique);
	wstring executable = directory + L"\\dwaglnc.exe";
	wstring source = dwPath + L"\\native\\dwaglnc.exe";
	if (!CopyFileW(source.c_str(), executable.c_str(), TRUE)){
		DWORD error = GetLastError();
		RemoveDirectoryW(directory.c_str());
		SetLastError(error);
		return false;
	}
	wstring command = L"\"" + executable + L"\" remove \"" + dwPath + L"\" "
		+ to_wstring(GetCurrentProcessId());
	STARTUPINFOW startup = {};
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION process = {};
	// The caller has already elevated. Keep that token and avoid session/token races.
	BOOL started = CreateProcessW(executable.c_str(), &command[0], NULL, NULL,
		FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, directory.c_str(), &startup, &process);
	if (!started){
		DWORD error = GetLastError();
		DeleteFileW(executable.c_str());
		RemoveDirectoryW(directory.c_str());
		SetLastError(error);
		return false;
	}
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	return true;
}

bool cleanupDirectoryIdentity(const wstring& path, BY_HANDLE_FILE_INFORMATION& identity){
	HANDLE directory = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (directory == INVALID_HANDLE_VALUE) return false;
	BOOL found = GetFileInformationByHandle(directory, &identity);
	DWORD error = GetLastError();
	CloseHandle(directory);
	if (!found){
		SetLastError(error);
		return false;
	}
	return (identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		&& !(identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool cleanupOwnerContents(const wstring& path, string& contents){
	HANDLE file = CreateFileW((path + L"\\setup-owner.json").c_str(), GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (file == INVALID_HANDLE_VALUE) return false;
	BY_HANDLE_FILE_INFORMATION info = {};
	bool valid = GetFileInformationByHandle(file, &info) != FALSE;
	DWORD error = valid ? ERROR_SUCCESS : GetLastError();
	if (valid && (info.nFileSizeHigh || !info.nFileSizeLow || info.nFileSizeLow > 65536
			|| (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))){
		valid = false;
		error = ERROR_INVALID_DATA;
	}
	contents.assign(valid ? info.nFileSizeLow : 0, '\0');
	DWORD read = 0;
	if (valid && !ReadFile(file, &contents[0], contents.size(), &read, NULL)){
		valid = false;
		error = GetLastError();
	}else if (valid && read != contents.size()){
		valid = false;
		error = ERROR_HANDLE_EOF;
	}
	CloseHandle(file);
	SetLastError(error);
	return valid;
}

bool cleanupGenerationMatches(const wstring& path, const BY_HANDLE_FILE_INFORMATION& expected,
		const string& expectedOwner, bool hasOwner, bool ownerRemoved = false){
	BY_HANDLE_FILE_INFORMATION current = {};
	if (!cleanupDirectoryIdentity(path, current)
			|| current.dwVolumeSerialNumber != expected.dwVolumeSerialNumber
			|| current.nFileIndexHigh != expected.nFileIndexHigh || current.nFileIndexLow != expected.nFileIndexLow
			|| CompareFileTime(&current.ftCreationTime, &expected.ftCreationTime) != 0) return false;
	if (hasOwner){
		string owner;
		if (!cleanupOwnerContents(path, owner)){
			DWORD error = GetLastError();
			// Only this helper may relax the marker check after removing it last.
			if (!ownerRemoved || (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)) return false;
		}else if (owner != expectedOwner) return false;
	}
	return true;
}

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

void loadProperties(wstring dwPath) {
	wstring appfn = dwPath;
	appfn.append(L"\\native\\service.properties");

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

			//Read properties
			int endpart1 = line.find_first_of(L"=");
			wstring part1 = line.substr(0, endpart1);
			trimAll(part1);
			wstring part2 = line.substr(endpart1 + 1);
			trimAll(part2);
			if (part1.compare(L"pythonPath") == 0) {
				pythonPath = part2;
			}
		}
	}else{
		throw "ERROR: Read properties error.";
	}
}

int wmain(int argc, wchar_t **argv) {
	try {
		if(argc > 1){
			wstring scommand = wstring(argv[1]);
			if (scommand.compare(L"remove")==0){
				if (argc>=3){
					wchar_t absolute[MAX_PATH];
					DWORD length = GetFullPathNameW(argv[2], MAX_PATH, absolute, NULL);
					if (length <= 3 || length >= MAX_PATH) return 2;
					wstring target(absolute);
					if (!existsFile(target + L"\\agent.uninstall")
                            || !existsFile(target + L"\\native\\service.properties")
                            || (GetFileAttributesW(absolute) & FILE_ATTRIBUTE_REPARSE_POINT)) return 2;
                    BY_HANDLE_FILE_INFORMATION generation = {};
                    if (!cleanupDirectoryIdentity(target, generation)) return 2;
                    bool hasOwner = existsFile(target + L"\\setup-owner.json");
                    bool ownerRemoved = false;
                    string owner;
                    if (hasOwner && !cleanupOwnerContents(target, owner)) return 2;
                    if (argc >= 4){
                        HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, wcstoul(argv[3], NULL, 10));
                        if (parent){
                            DWORD waited = WaitForSingleObject(parent, 30000);
                            CloseHandle(parent);
                            if (waited != WAIT_OBJECT_0) return 3;
                        }
                    }
                    for (int attempt=0; attempt<15; ++attempt){
                        Sleep(2000);
                        // A newer installation may reuse the same pathname.
                        if (!cleanupGenerationMatches(target, generation, owner, hasOwner, ownerRemoved)) return 2;
                        deleteDir(absolute, hasOwner, &ownerRemoved);
                        if (GetFileAttributesW(absolute) == INVALID_FILE_ATTRIBUTES) return 0;
                    }
					return 1;
				}
				return 0;
			}
			SetEnvironmentVariableW(L"PYTHONHOME", L"runtime");
			wstring dwPath = getDWAgentPath();
			loadProperties(dwPath);
			wstring cmd=L"";
			if (scommand.compare(L"monitor")==0){
				cmd=L"-S -m monitor window";
				// The GUI creates its own windows; do not show the runtime console.
				ShellExecuteW(GetDesktopWindow(), L"open", pythonPath.c_str(), cmd.c_str(), dwPath.c_str() , SW_HIDE);
			}else if (scommand.compare(L"systray")==0){
				cmd=L"-S -m monitor systray";
				ShellExecuteW(GetDesktopWindow(), L"open", pythonPath.c_str(), cmd.c_str(), dwPath.c_str() , SW_HIDE);
			}else if (scommand.compare(L"configure")==0){
				cmd=L"-S -m configure";
				ShellExecuteW(GetDesktopWindow(), L"open", pythonPath.c_str(), cmd.c_str(), dwPath.c_str() , SW_HIDE);
			}else if (scommand.compare(L"uninstallAsAdimn")==0){
				SHELLEXECUTEINFOW ShExecInfo = {0};
				ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
				ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
				ShExecInfo.hwnd = NULL;
				ShExecInfo.lpVerb = NULL;
				ShExecInfo.lpFile = pythonPath.c_str();
				ShExecInfo.lpParameters = existsFile(dwPath + L"\\setup-access.json")
					? L"-S -m support_setup uninstall" : L"-S -m installer uninstall";
				ShExecInfo.lpDirectory = dwPath.c_str();
				ShExecInfo.nShow = SW_HIDE;
				ShExecInfo.hInstApp = NULL;
				if (!ShellExecuteExW(&ShExecInfo) || !ShExecInfo.hProcess) return 1;
				DWORD waited = WaitForSingleObject(ShExecInfo.hProcess,INFINITE);
				CloseHandle(ShExecInfo.hProcess);
				if (waited != WAIT_OBJECT_0) return 1;
				//Elimina cartella lanciando l'applicazione da temp
				wstring fln = dwPath;
				fln.append(L"\\").append(L"agent.uninstall");
				if (existsFile(fln)){
					if (!startRemove(dwPath)) return 1;
				}
			}else if (scommand.compare(L"uninstall")==0){
				//Rilancia L'Applicazione come Amministratore
				SHELLEXECUTEINFOW ShExecInfo = {0};
				ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
				ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
				ShExecInfo.hwnd = NULL;
				if (isRunAsAdmin()){
					ShExecInfo.lpVerb  = NULL;
				}else{
					ShExecInfo.lpVerb  = L"runas";
				}
				ShExecInfo.lpFile = L"native\\dwaglnc.exe";
				ShExecInfo.lpParameters = L"uninstallAsAdimn";
				ShExecInfo.lpDirectory = dwPath.c_str();
				ShExecInfo.nShow = SW_SHOW;
				ShExecInfo.hInstApp = NULL;
				ShellExecuteExW(&ShExecInfo);
			}
		}
	} catch (...) {
		return 1;
	}
    return 0;
}

