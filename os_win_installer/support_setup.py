"""Password-protected Windows setup using the agent's existing installer engine."""

import json
import hashlib
import ctypes
from ctypes import wintypes
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import os
import time
from contextlib import contextmanager

from ui import installer, ui
from setup_auth import (valid_access_config, verify_access_password,
                        PasswordServerUnavailable, DEFAULT_INSTALL_IDENTITY,
                        validate_install_identity, validate_install_path)
from setup_files import (verify_protected_directory, verify_no_reparse_points,
                         rename_with_retry)
from setup_version import format_display_name, set_executable_description


ACCESS_FILE = "setup-access.json"
APP_TITLE = "REMO"
INCORRECT_PASSWORD_MESSAGE = "Incorrect P."


def program_files_directory():
    """Read the protected OS directory instead of a caller-supplied environment."""
    api = ctypes.windll.shell32.SHGetFolderPathW
    api.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE,
                    wintypes.DWORD, wintypes.LPWSTR]
    api.restype = ctypes.c_long
    buffer = ctypes.create_unicode_buffer(260)
    if api(None, 0x26, None, 0, buffer) != 0 or not buffer.value:
        raise ValueError("Cannot locate the Windows Program Files directory.")
    return Path(buffer.value)


class SupportWindows(installer.NativeWindows):
    def __init__(self):
        super().__init__()
        self._service_executable = "dwagsvc.exe"
        self._install_identity = None
        self._format_display_names = False
        self._service_tool_path = None
        self.last_service_error = ""

    def set_name(self, name):
        super().set_name(name)
        if self._install_identity and name == self._install_identity["service_name"]:
            self._runtime = self._install_identity["main_executable"]

    def set_install_identity(self, identity, *, format_display_names=False):
        self._install_identity = validate_install_identity(identity)
        self._format_display_names = bool(format_display_names)
        self.set_name(self._install_identity["service_name"])
        self.set_service_executable(self._install_identity["service_executable"])

    def get_service_display_name(self):
        value = self._install_identity["service_display_name"]
        return format_display_name(value) if self._format_display_names else value

    def prepare_file(self):
        super().prepare_file()
        if self._install_identity:
            properties = Path(self._install_path) / "native" / "service.properties"
            with properties.open("a", encoding="utf-8") as stream:
                stream.write("\nserviceDisplayName=" + self.get_service_display_name() + "\n")
                stream.write("publisher=" + self._install_identity.get("publisher", "DWService") + "\n")

    def set_service_executable(self, name):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+\.exe", name, re.IGNORECASE):
            raise ValueError("Invalid service executable filename.")
        self._service_executable = name

    def _service_command(self, action):
        executable = (self._service_tool_path or
                      Path(self._install_path) / "native" / self._service_executable)
        return self.executecmd(subprocess.list2cmdline([str(executable), action]))

    def executecmd(self, command):
        self.last_service_error = ""
        process = installer.NativeWindowsPopenUnicode(command, shell=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errors = process.communicate()
        lines = output.decode("utf-8", errors="replace").splitlines()
        if "OK" in lines:
            return True
        self.last_service_error = ("\n".join(lines) + "\n" +
                                  errors.decode("utf-8", errors="replace")).strip()[-600:]
        return False

    def get_service_image_path(self):
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        api.OpenSCManagerW.restype = wintypes.HANDLE
        api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        api.OpenServiceW.restype = wintypes.HANDLE
        api.QueryServiceConfigW.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.QueryServiceConfigW.restype = wintypes.BOOL
        api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        api.CloseServiceHandle.restype = wintypes.BOOL
        manager = api.OpenSCManagerW(None, None, 1)
        if not manager:
            raise ctypes.WinError(ctypes.get_last_error())
        service = None
        try:
            service = api.OpenServiceW(manager, self._name, 1)
            if not service:
                error = ctypes.get_last_error()
                if error == 1060:
                    return None
                raise ctypes.WinError(error)
            needed = wintypes.DWORD()
            api.QueryServiceConfigW(service, None, 0, ctypes.byref(needed))
            if not 0 < needed.value <= 65536:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(needed.value)
            if not api.QueryServiceConfigW(service, buffer, needed, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            class Config(ctypes.Structure):
                _fields_ = [("service_type", wintypes.DWORD), ("start_type", wintypes.DWORD),
                            ("error_control", wintypes.DWORD), ("binary", wintypes.LPWSTR)]
            return ctypes.cast(buffer, ctypes.POINTER(Config)).contents.binary
        finally:
            if service:
                api.CloseServiceHandle(service)
            api.CloseServiceHandle(manager)

    def install_service(self):
        return self._service_command("installService")

    def start_service(self):
        return self._service_command("startService")

    def stop_service(self):
        return self._service_command("stopService")

    def delete_service(self):
        return self._service_command("deleteService")

    def get_service_state(self):
        """Read the actual Windows service state; None means absent/deleting."""
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        api.OpenSCManagerW.restype = wintypes.HANDLE
        api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        api.OpenServiceW.restype = wintypes.HANDLE
        api.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        api.QueryServiceStatus.restype = wintypes.BOOL
        api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        api.CloseServiceHandle.restype = wintypes.BOOL
        manager = api.OpenSCManagerW(None, None, 1)
        if not manager:
            raise ctypes.WinError(ctypes.get_last_error())
        service = None
        try:
            service = api.OpenServiceW(manager, self._name, 4)
            if not service:
                error = ctypes.get_last_error()
                if error in (1060, 1072):
                    return None
                raise ctypes.WinError(error)
            status = (wintypes.DWORD * 7)()
            if not api.QueryServiceStatus(service, status):
                raise ctypes.WinError(ctypes.get_last_error())
            return status[1]
        finally:
            if service:
                api.CloseServiceHandle(service)
            api.CloseServiceHandle(manager)

    def install_auto_run_monitor(self):
        result = self._service_command("installAutoRun")
        if result:
            launcher = Path(self._install_path) / "native" / "dwaglnc.exe"
            command = subprocess.list2cmdline([str(launcher), "systray"])
            installer.NativeWindowsPopenUnicode(
                command, shell=True, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        return result

    def remove_auto_run_monitor(self):
        return self._service_command("removeAutoRun")

    def install_shortcuts(self):
        return self._service_command("installShortcuts")

    def remove_shortcuts(self):
        return self._service_command("removeShortcuts")


def setup_inputs():
    screen = ui.Inputs()
    advance = screen.fire_next_step

    # The upstream UI dispatches by exact class name, including after updates.
    def validate_and_advance():
        for field in screen.get_inputs():
            if field["mandatory"] and not (field["variable"].get() or "").strip():
                return ui.ErrorDialog("The field {0} is required.".format(field["label"]))
        return advance()

    screen.fire_next_step = validate_and_advance
    return screen


def password_screen(variable, callback, removal=False):
    screen = setup_inputs()
    screen.set_key("setupPassword")
    screen.set_message("we miss you" if removal
                       else APP_TITLE)
    screen.add("password", "P", variable, True)
    screen.next_step(callback)
    return screen


class SupportInstall(installer.Install):
    def __init__(self):
        super().__init__()
        self._native = SupportWindows()
        self._optional_reference = ui.VarString("")
        self._setup_password = ui.VarString("", True)
        self._install_code = ui.VarString("", True)
        self._setup_authorized = False
        self._files_installed = False
        self._destination_checked = False
        self._created_service_name = None
        self._authorized_code = None
        self._replacement = None
        self._replacement_backup = None

    def _get_message(self, key):
        return installer.messages.get_message(key).replace("DWAgent", APP_TITLE)

    def step_init(self, current):
        if self._silent:
            return ui.Message("Open setup interactively to enter the password.")
        if not valid_access_config(self._options):
            return ui.Message("The setup password configuration is missing or invalid.")
        if self._options.get("server_install_identity"):
            self._apply_install_identity(DEFAULT_INSTALL_IDENTITY)
        self._native.set_service_executable(self._options.get("service_executable", "dwagsvc.exe"))
        # Elevate before collecting credentials so a relaunch cannot lose them.
        error = self._native.check_init_install()
        if error is not None:
            return ui.Message(error)
        return self.step_code(current)

    def step_password(self, current):
        entered_password = self._setup_password.get()
        self._setup_authorized = False
        self._authorized_code = None
        # This field is only a user-visible note. Never send or persist it.
        self._optional_reference.set("")
        self._setup_password.set("")
        code = (self._install_code.get() or "").strip().replace(" ", "")
        if self._options.get("combined_password_code") and not code:
            return ui.ErrorDialog("The field C is required.")
        identity = None
        if self._options.get("server_install_identity"):
            if not self._files_installed:
                self._apply_install_identity(DEFAULT_INSTALL_IDENTITY)
                self._destination_checked = False
            identity = {}
        try:
            if identity is None:
                allowed = verify_access_password(entered_password, self._options)
            else:
                allowed = verify_access_password(entered_password, self._options, install_identity=identity)
        except PasswordServerUnavailable as error:
            return ui.ErrorDialog(str(error))
        if not allowed:
            return ui.ErrorDialog(INCORRECT_PASSWORD_MESSAGE)
        if identity and not self._files_installed:
            self._apply_install_identity(identity)
        self._setup_authorized = True
        self._authorized_code = code
        if self._options.get("combined_password_code"):
            return self.step_begin(current)
        return self.step_code(current)

    def _apply_install_identity(self, identity):
        identity = validate_install_identity(identity)
        self._name = identity["service_name"]
        self._options["name"] = self._name
        self._options["service_executable"] = identity["service_executable"]
        self._options["install_identity"] = identity
        self._native.set_install_identity(identity, format_display_names=
                                        self._options.get("process_description_from_filename", False))

    def step_code(self, current):
        if self._options.get("combined_password_code"):
            self._setup_authorized = False
            self._authorized_code = None
            self._setup_password.set("")
        screen = setup_inputs()
        screen.set_key("supportCode")
        action = "next" if not self._setup_authorized or self._files_installed else "install"
        screen.set_param("next_label", self._get_message(action))
        notice = (
            "REMO\n"
            "Hi, Nice to meet you")
        screen.set_message(self._add_message_markdown_hyperlink(screen, notice))
        screen.set_message_height(150)
        if self._install_code.get() is None:
            self._install_code.set("")
        if self._options.get("combined_password_code"):
            screen.set_param("next_label", self._get_message("next" if self._files_installed else "install"))
            screen.add("password", "P", self._setup_password, True)
            screen.add("code", "C", self._install_code, True)
            screen.next_step(self.step_password)
        elif not self._setup_authorized:
            screen.add("reference", "Optional reference", self._optional_reference, False)
            screen.add("password", "Enter the password", self._setup_password, True)
            screen.next_step(self.step_password)
        else:
            screen.add("code", "c", self._install_code, True)
            screen.next_step(self.step_begin)
        return screen

    def step_begin(self, current):
        if not self._setup_authorized:
            return self.step_init(current)
        code = (self._install_code.get() or "").strip().replace(" ", "")
        if not code:
            return ui.ErrorDialog("The field c is required.")
        if self._options.get("combined_password_code") and code != self._authorized_code:
            return self.step_code(current)
        self._install_code.set(code)
        self._inatall_agent_mode = "installCode"
        if self._files_installed:
            current.set_param("firstConfig", True)
            return self.step_config_install_request(current)
        if not self._destination_checked:
            replacing = self._options.get("replace_existing_installation", False)
            if not replacing and self._native.get_install_path() is not None:
                return ui.Message("Remote support is already installed. Remove it before reinstalling.")
            if not replacing and self._options.get("server_install_identity") and self._native.get_service_state() is not None:
                return ui.Message("A Windows service already uses this name. Choose a different name in the portal.")
            folder = self._name if self._options.get("server_install_identity") else "Notepad+"
            try:
                destination = self._resolve_destination(folder)
                self._replacement = self._plan_replacement(destination) if replacing else None
            except (OSError, ValueError) as error:
                return ui.Message(str(error))
            # The upstream engine removes existing folders; never do that silently.
            if destination.exists() and self._replacement is None:
                return ui.Message("The default installation folder already exists. "
                                  "Remove the previous installation before continuing.")
            self._install_path.set(str(destination))
            self._destination_checked = True
        return self.step_install(current)

    def _resolve_destination(self, folder):
        selected = self._options.get("install_identity", {}).get("install_path", "")
        validate_install_path(selected)
        protected = self._options.get("install_identity_version") == 2
        base = program_files_directory() if protected else Path(os.environ["ProgramFiles"])
        if selected.lower().startswith("%programfiles%\\"):
            selected = str(base) + selected[len("%ProgramFiles%"):]
        destination = Path(selected) if selected else base / folder
        if self._options.get("server_install_identity"):
            validate_install_path(str(destination))
            self._validate_destination(destination)
            if protected:
                self._validate_protected_destination(destination, base)
        return destination

    def _validate_protected_destination(self, destination, base):
        if base not in destination.parents:
            raise ValueError("Choose new application subfolders inside the Windows Program Files directory.")
        # Existing vendor folders can have weaker permissions than Program Files.
        for parent in destination.parents:
            if parent != base and base in parent.parents and parent.exists():
                if not self._options.get("replace_existing_installation"):
                    raise ValueError("Choose new application subfolders directly under Program Files.")
                verify_protected_directory(parent)
        units = len(str(destination).encode("utf-16-le")) // 2
        if units > min(180, 246 - len(self._name)):
            raise ValueError("The installation path is too long for the selected Windows service name.")

    def _validate_destination(self, destination):
        # Refuse redirected paths and nonlocal volumes before creating files.
        root = destination.anchor
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
        if get_drive_type(root) != 3:
            raise ValueError("The installation folder must be on a local fixed drive.")
        windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        if destination == windows or windows in destination.parents:
            raise ValueError("Choose an application folder outside the Windows directory.")
        for ancestor in (destination,) + tuple(destination.parents):
            try:
                attributes = ancestor.lstat().st_file_attributes
            except FileNotFoundError:
                continue
            if attributes & 0x400:
                raise ValueError("The installation folder cannot pass through a junction or symbolic link.")

    def step_install(self, current):
        if not self._setup_authorized or not self._destination_checked:
            return self.step_begin(current)
        return super().step_install(current)

    def step_check_already_install(self, current):
        return self.step_code(current)

    def step_check_install_path(self, current):
        return self.step_code(current)

    def _make_directory(self, start, end):
        if not self._options.get("server_install_identity") or self._bmock:
            return super()._make_directory(start, end)
        # A naming profile must never cause the upstream installer to remove a folder.
        self._uinterface.wait_message(self._get_message("pathCreating"), None, end)
        destination = Path(self._install_path.get())
        self._validate_destination(destination)
        if self._options.get("install_identity_version") == 2:
            self._validate_protected_destination(destination, program_files_directory())
        if self._replacement is not None:
            self._prepare_replacement(destination)
        destination.mkdir(parents=True)
        if self._options.get("replace_existing_installation"):
            marker = {"format": 1, "installation_id": os.urandom(16).hex(),
                      "remote_password": self._options.get("remote_password"),
                      "install_identity": self._options["install_identity"]}
            if self._options.get("process_description_from_filename"):
                marker["process_description_from_filename"] = True
            (destination / "setup-owner.json").write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")

    def _plan_replacement(self, destination):
        if not self._setup_authorized:
            raise ValueError("Enter P and C before replacing an installation.")
        registered = self._native.get_install_path()
        state = self._native.get_service_state()
        if registered is not None and Path(registered) != destination:
            raise ValueError("The selected service is registered in another folder. Remove that installation first.")
        if not destination.exists():
            if registered is not None or state is not None:
                raise ValueError("The selected service already exists without a matching installation folder.")
            return None
        verify_protected_directory(destination)
        verify_no_reparse_points(destination, recursive=True)
        if not any(destination.iterdir()) and registered is None and state is None:
            return {"native": None, "identity": None, "fingerprint": "empty"}
        access_path = destination / ACCESS_FILE
        if not access_path.is_file():
            access_path = destination / "setup-owner.json"
        try:
            if access_path.stat().st_size > 65536:
                raise ValueError("Installation ownership record is too large.")
            record_bytes = access_path.read_bytes()
            access = json.loads(record_bytes.decode("utf-8"))
            identity = validate_install_identity(access["install_identity"])
            if (not isinstance(self._options.get("remote_password"), dict)
                    or access.get("remote_password") != self._options["remote_password"]):
                raise ValueError("The folder belongs to a different password portal.")
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError("The existing folder could not be verified as your installation. "
                             "Its files were kept. Choose another folder in the portal.") from error
        properties_path = destination / "native" / "service.properties"
        properties_bytes = b""
        if properties_path.exists():
            if properties_path.stat().st_size > 16384:
                raise ValueError("Invalid existing service properties.")
            properties_bytes = properties_path.read_bytes()
            properties = dict(line.split("=", 1) for line in properties_bytes.decode("utf-8").splitlines() if "=" in line)
            expected_runtime = destination / "runtime" / identity["main_executable"]
            if (properties.get("serviceName") != identity["service_name"]
                    or Path(properties.get("pythonPath", "")) != expected_runtime):
                raise ValueError("The existing service properties do not match its ownership record.")
        elif access_path.name != "setup-owner.json":
            raise ValueError("The existing folder has no verifiable service properties.")
        if identity["service_name"] != self._name and (registered is not None or state is not None):
            raise ValueError("Another Windows service already uses the new service name.")
        old_native = SupportWindows()
        old_native.set_install_identity(identity, format_display_names=
                                        access.get("process_description_from_filename", False))
        old_native.set_install_path(str(destination))
        old_registered = old_native.get_install_path()
        if old_registered is not None and Path(old_registered) != destination:
            raise ValueError("The existing application's registration points to another folder.")
        image = old_native.get_service_image_path()
        executable = str(destination / "native" / identity["service_executable"])
        expected = {subprocess.list2cmdline([executable, "run"]).casefold(),
                    ('"' + executable + '" run').casefold()}
        if image is not None and image.strip().casefold() not in expected:
            raise ValueError("The existing Windows service points to another executable. It was kept.")
        return {"native": old_native, "identity": identity,
                "fingerprint": hashlib.sha256(record_bytes + properties_bytes).hexdigest()}

    @contextmanager
    def _replacement_tool(self, native):
        # Use the fresh bundled helper; never run a binary from the old folder.
        source = Path(__file__).resolve().parent / installer._NATIVE_PATH / "dwagsvc.exe"
        if not source.is_file():
            source = Path(__file__).resolve().parent / "native_win_x86_64" / "dwagsvc.exe"
        with tempfile.TemporaryDirectory(prefix="REMO-Service-", dir=str(program_files_directory())) as temporary:
            folder = Path(temporary) / "native"
            folder.mkdir()
            executable = folder / "dwagsvc.exe"
            shutil.copy2(source, executable)
            identity = native._install_identity
            properties = {"serviceName": native._name, "workPath": native._install_path,
                          "serviceDisplayName": native.get_service_display_name(),
                          "publisher": identity.get("publisher", "DWService"),
                          "pythonPath": str(Path(native._install_path) / "runtime" / identity["main_executable"])}
            (folder / "service.properties").write_text(
                "".join(key + "=" + value + "\n" for key, value in properties.items()), encoding="utf-8")
            native._service_tool_path = executable
            try:
                yield
            finally:
                native._service_tool_path = None

    def _prepare_replacement(self, destination):
        if not self._setup_authorized:
            raise ValueError("Replacement requires password authorization.")
        plan = self._plan_replacement(destination)
        if plan is None or plan["fingerprint"] != self._replacement["fingerprint"]:
            raise ValueError("The existing installation changed. Run setup again.")
        backup = destination.with_name(destination.name + ".previous-" + time.strftime("%Y%m%d-%H%M%S")
                                       + "-" + os.urandom(3).hex())
        native = plan["native"]
        if native is None:
            rename_with_retry(destination, backup)
        else:
            pending_cleanup = (destination / "agent.uninstall").exists()
            with self._replacement_tool(native):
                previous_state = native.get_service_state()
                installer.stop_monitor(str(destination))
                if not native.stop_service():
                    raise RuntimeError("Cannot stop the previous service. " + native.last_service_error)
                try:
                    rename_with_retry(destination, backup)
                except (OSError, ValueError):
                    if previous_state == 4:
                        native.start_service()
                    raise
                self._replacement_backup = backup
                for action in (native.remove_auto_run_monitor, native.remove_shortcuts, native.delete_service):
                    if not action():
                        failure = native.last_service_error
                        rename_with_retry(backup, destination)
                        self._replacement_backup = None
                        # The service has not been deleted on a registration failure.
                        # Restore any app entries already removed before that failure.
                        native.install_shortcuts()
                        native._service_command("installAutoRun")
                        if previous_state == 4:
                            native.start_service()
                        raise RuntimeError("Cannot finish replacing the previous installation. " + failure)
            if pending_cleanup:
                # Older cleanup helpers can still target the old path for 60 seconds.
                self._uinterface.wait_message("Waiting for the previous uninstall to finish...", None, None)
                time.sleep(65)
        self._replacement_backup = backup
        self._replacement = None
        self._append_log("Previous installation preserved at " + str(backup))

    def _install_service(self, start, end):
        if not self._options.get("server_install_identity") or self._bmock:
            return super()._install_service(start, end)
        # CreateService is atomic. Never stop or delete a pre-existing service.
        self._uinterface.wait_message(self._get_message("installService"), None, start)
        if self._created_service_name != self._name:
            if self._native.get_service_state() is not None:
                raise ValueError("A Windows service already uses the selected name.")
            if not self._native.install_service():
                raise ValueError(self._get_message("installServiceErr"))
            self._created_service_name = self._name
        self._uinterface.wait_message(self._get_message("startService"), None, end)
        if not self._native.start_service():
            raise ValueError(self._get_message("startServiceErr"))

    def _rename_installed_component(self, directory, original, selected):
        if original.lower() == selected.lower():
            return
        destination = Path(self._install_path.get()) / directory
        target = destination / selected
        if target.exists():
            raise ValueError("The selected executable filename is already in use.")
        (destination / original).rename(target)

    def copy_runtime(self, start, end):
        super().copy_runtime(start, end)
        if self._options.get("server_install_identity") and not self._bmock:
            self._rename_installed_component("runtime", "dwagent.exe",
                                             self._options["install_identity"]["main_executable"])
            self._set_installed_process_description("runtime", "main_executable")

    def copy_native(self, start, end):
        super().copy_native(start, end)
        if self._options.get("server_install_identity") and not self._bmock:
            self._rename_installed_component("native", "dwagsvc.exe",
                                             self._options["install_identity"]["service_executable"])
            self._set_installed_process_description("native", "service_executable")

    def _set_installed_process_description(self, directory, filename_key):
        if not self._options.get("dynamic_process_description"):
            return
        identity = validate_install_identity(self._options["install_identity"])
        executable = Path(self._install_path.get()) / directory / identity[filename_key]
        display_name = (format_display_name(identity[filename_key])
                        if self._options.get("process_description_from_filename")
                        else identity["service_display_name"])
        # Update the installed copy before any process or service starts. The
        # friendly description is separate from the mandatory .exe filename.
        try:
            set_executable_description(executable, display_name, product_name=display_name)
        except (OSError, ValueError) as error:
            raise RuntimeError("Cannot set the Task Manager name for " +
                               executable.name + ": " + str(error)) from error

    def _download_files(self, start, end):
        super()._download_files(start, end)
        destination = Path(self._install_path.get())
        source = Path(__file__).resolve().parent
        for name in ("support_setup.py", "setup_auth.py", "setup_files.py", "setup_version.py", "uninstall.cmd"):
            shutil.copy2(source / name, destination / name)
        # Keep the custom progress UI and tray status after the agent download.
        (destination / "ui").mkdir(exist_ok=True)
        for name in ("ui.py", "monitor.py"):
            source_ui = source / "ui" / name
            if not source_ui.is_file():
                source_ui = source.parent / "ui" / name
            shutil.copy2(source_ui, destination / "ui" / name)
        access = {key: self._options[key] for key in ("remote_password", "setup_password", "recovery_password")
                  if key in self._options}
        access["service_executable"] = self._options.get("service_executable", "dwagsvc.exe")
        if self._options.get("server_install_identity"):
            access["install_identity"] = validate_install_identity(self._options["install_identity"])
            if self._options.get("process_description_from_filename"):
                access["process_description_from_filename"] = True
        (destination / ACCESS_FILE).write_text(
            json.dumps(access, indent=2) + "\n",
            encoding="utf-8")

    def step_config_init(self, current):
        self._files_installed = True
        self._inatall_agent_mode = "installCode"
        return self.step_config_install_request(current)

    def step_config_install_request(self, current):
        result = super().step_config_install_request(current)
        if isinstance(result, ui.Message) and result.get_message() == self._get_message("endInstall"):
            result.set_param("auto_close", True)
        return result

    def step_config(self, current):
        if current.get_param("tryAgain", False) and current.get_variable().get() == "configureLater":
            return ui.Message("Remote support is installed but has not been linked to an account.")
        return self.step_code(current)


class SupportUninstall(installer.Uninstall):
    def __init__(self):
        super().__init__()
        self._native = SupportWindows()
        self._setup_password = ui.VarString("", True)
        self._setup_authorized = False
        self._password_record = None
        self._access_config = None
        self._removal_complete = False

    def _get_message(self, key):
        if key == "titleUninstall":
            return APP_TITLE
        return installer.messages.get_message(key).replace("DWAgent", APP_TITLE)

    def start(self, options=None):
        self._terminal_mode = bool((options or {}).get("terminal_uninstall"))
        self._load_access_config()
        options = dict(options or {})
        options["progress_only"] = True
        return super().start(options)

    def _load_access_config(self):
        try:
            access = json.loads((Path(__file__).resolve().parent / ACCESS_FILE).read_text(encoding="utf-8"))
            self._password_record = access.get("setup_password")
            self._access_config = access
            self._native.set_service_executable(access.get("service_executable", "dwagsvc.exe"))
            if "install_identity" in access:
                self._native.set_install_identity(access["install_identity"], format_display_names=
                                                 access.get("process_description_from_filename", False))
        except (OSError, ValueError, AttributeError):
            self._password_record = None
            self._access_config = None

    def step_init(self, current):
        if self._silent:
            return ui.Message("Open the uninstaller interactively to enter the password.")
        if not valid_access_config(self._access_config or {"setup_password": self._password_record}):
            return ui.Message("The uninstall password configuration is missing or invalid.")
        return password_screen(self._setup_password, self.step_password, removal=True)

    def step_password(self, current):
        entered_password = self._setup_password.get()
        self._setup_password.set("")
        self._setup_authorized = False
        self._removal_complete = False
        try:
            allowed = verify_access_password(entered_password,
                self._access_config or {"setup_password": self._password_record})
        except PasswordServerUnavailable as error:
            return ui.ErrorDialog(str(error))
        if not allowed:
            return ui.ErrorDialog(INCORRECT_PASSWORD_MESSAGE)
        self._setup_password.set("")
        error = self._native.check_init_uninstall()
        if error is not None:
            return ui.Message(error)
        install_path = self._native.get_install_path()
        if install_path is None:
            return ui.Message(self._get_message("notInstalled"))
        self._install_path = str(install_path)
        self._setup_authorized = True
        if getattr(self, "_terminal_mode", False):
            # The worker is detached before stopping the service that hosts DW Terminal.
            executable = sys.executable
            worker = subprocess.Popen([str(executable), "-S", "-m", "support_setup", "-console-worker"],
                cwd=self._install_path, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB)
            worker.communicate(json.dumps({"password": entered_password}).encode("utf-8"))
            if worker.returncode != 0:
                return ui.ErrorDialog("Uninstall could not complete. Check console-uninstall.log in the installation folder.")
            self._removal_complete = True
            result = ui.Message(self._get_message("endUninstall"))
            result.set_param("auto_close", True)
            return result
        # Entering a valid password is the confirmation for this custom flow.
        return self.step_remove(current)

    def step_remove(self, current):
        if not self._setup_authorized:
            return self.step_init(current)
        result = super().step_remove(current)
        if isinstance(result, ui.Message) and result.get_message() == self._get_message("endUninstall"):
            self._removal_complete = True
            result.set_param("auto_close", True)
        return result

    def _uninstall_service(self, start, end):
        self._uinterface.wait_message(self._get_message("uninstallService"), None, start)
        state = self._native.get_service_state()
        if state is None:
            return
        if state != 1:  # SERVICE_STOPPED
            stopped = self._native.stop_service()
            deadline = time.monotonic() + 15
            state = self._native.get_service_state()
            while stopped and state not in (None, 1) and time.monotonic() < deadline:
                time.sleep(0.2)
                state = self._native.get_service_state()
            if not stopped or state not in (None, 1):
                raise RuntimeError("Windows could not stop the remote support service. "
                                   "Uninstallation did not complete. " + self._service_error())
            if state is None:
                return
        deleted = self._native.delete_service()
        if not deleted or self._native.get_service_state() is not None:
            raise RuntimeError("Windows could not remove the remote support service. "
                               "Uninstallation did not complete. " + self._service_error())

    def _uninstall_shortcuts(self, start, end):
        self._uinterface.wait_message(self._get_message("uninstallShortcuts"), None, start)
        removed = self._native.remove_shortcuts()
        if not removed or self._native.get_install_path() is not None:
            raise RuntimeError("Windows could not remove the application's registration. "
                               "Uninstallation did not complete. " + self._service_error())

    def _service_error(self):
        detail = getattr(self._native, "last_service_error", "")
        if not isinstance(detail, str) or not detail:
            return "Check unistall.log for the Windows error."
        match = re.search(r"Windows error (\d+)", detail)
        if match:
            explanation = ctypes.FormatError(int(match.group(1))).strip()
            if explanation:
                return detail + ": " + explanation
        return detail


def schedule_console_cleanup(install_path):
    target = Path(install_path).resolve()
    # Only clean the installation containing this authenticated uninstaller.
    if (target != Path(__file__).resolve().parent or target == target.parent
            or not (target / "agent.uninstall").is_file()
            or not (target / "native" / "service.properties").is_file()):
        raise RuntimeError("Uninstall cleanup path could not be verified.")
    cleanup_directory = Path(tempfile.mkdtemp(prefix="REMO-uninstall-"))
    cleanup_executable = cleanup_directory / "dwaglnc.exe"
    shutil.copy2(target / "native" / "dwaglnc.exe", cleanup_executable)
    subprocess.Popen([str(cleanup_executable), "remove", str(target), str(os.getpid())],
                     cwd=str(cleanup_directory), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_BREAKAWAY_FROM_JOB)


def fmain(arguments):
    if "-console-worker" in arguments:
        run_console_worker()
        return
    removal = any(argument.lower() == "uninstall" for argument in arguments[1:])
    options = {"gui": "-console" not in arguments,
               "silent": "-silent" in arguments}
    if removal:
        uninstaller = SupportUninstall()
        if "-console" in arguments:
            raise SystemExit(run_terminal_uninstall(uninstaller))
        options["terminal_uninstall"] = "-console" in arguments
        uninstaller.start(options)
    else:
        SupportInstall().start(options)


def run_terminal_uninstall(uninstaller=None):
    """Small terminal flow with immediate retry and no extra Enter prompts."""
    uninstaller = uninstaller or SupportUninstall()
    uninstaller._terminal_mode = True
    uninstaller._load_access_config()
    try:
        config = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))
        uninstaller._native.set_name(config.get("name", "DWAgent"))
        if uninstaller._native.check_init_uninstall() is not None:
            print("Administrator rights required. Please try again using an Administrator Command Prompt (Run as administrator).")
            return 1
        if not valid_access_config(uninstaller._access_config or {"setup_password": uninstaller._password_record}):
            print("Uninstall failed: the password configuration is missing or invalid.")
            return 1
        print("Remove REMO remote-access software. Enter the password")
        while True:
            uninstaller._setup_password.set(ui.read_password("Password: "))
            result = uninstaller.step_password(ui.BaseUI())
            if uninstaller._removal_complete:
                print("Uninstall completed successfully.")
                return 0
            if isinstance(result, ui.ErrorDialog) and result.get_message() == INCORRECT_PASSWORD_MESSAGE:
                print("Incorrect password. Please try again.")
                continue
            print("Uninstall failed: " + result.get_message())
            return 1
    except (KeyboardInterrupt, EOFError):
        print("\nUninstall cancelled.")
        return 130
    except Exception as error:
        print("Uninstall failed: " + str(error))
        return 1


def run_console_worker():
    """Recheck credentials over a private pipe, remove the app, then schedule cleanup."""
    class QuietProgress:
        def wait_message(self, *args, **kwargs):
            pass
    try:
        payload = json.loads(sys.stdin.buffer.read(8192))
        uninstaller = SupportUninstall()
        uninstaller._load_access_config()
        config = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))
        uninstaller._native.set_name(config.get("name", "DWAgent"))
        uninstaller._silent = True
        uninstaller._install_log = None
        uninstaller._uinterface = QuietProgress()
        uninstaller._setup_password.set(payload.get("password", ""))
        result = uninstaller.step_password(ui.BaseUI())
        if not uninstaller._removal_complete:
            raise RuntimeError(result.get_message())
        schedule_console_cleanup(uninstaller._install_path)
    except Exception as error:
        (Path(__file__).parent / "console-uninstall.log").write_text(str(error), encoding="utf-8")
        raise SystemExit(1)


if __name__ == "__main__":
    fmain(sys.argv)
