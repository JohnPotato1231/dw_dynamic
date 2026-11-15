"""Verify process metadata on disposable real executables, without starting agents."""

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_support_setup as fixtures
import setup_version


NATIVE = fixtures.ROOT / "make" / "tmp" / "dynamic-10443-v3" / "native" / "dwagsvc.exe"
if not NATIVE.is_file():
    NATIVE = fixtures.ROOT / "make" / "native" / "dwagsvc.exe"
RUNTIME = fixtures.ROOT / "installer_payload_20260926221211" / "runtimepy3" / "bit64" / "dwagent.exe"
VERSION_KEYS = ("FileDescription", "ProductName", "FileVersion", "ProductVersion",
                "CompanyName", "OriginalFilename", "InternalName", "LegalCopyright")


def windows_version(path):
    """Read metadata through Windows version.dll, independently of the writer/parser."""
    api = ctypes.WinDLL("version", use_last_error=True)
    api.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    api.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    api.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    api.GetFileVersionInfoW.restype = wintypes.BOOL
    api.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                 ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
    api.VerQueryValueW.restype = wintypes.BOOL
    unused = wintypes.DWORD()
    size = api.GetFileVersionInfoSizeW(str(path), ctypes.byref(unused))
    if not size:
        return {"fixed": None, "translations": (), "strings": {}}
    buffer = ctypes.create_string_buffer(size)
    if not api.GetFileVersionInfoW(str(path), 0, size, buffer):
        raise ctypes.WinError(ctypes.get_last_error())

    def query(name, text=False):
        address, length = ctypes.c_void_p(), wintypes.UINT()
        if not api.VerQueryValueW(buffer, name, ctypes.byref(address), ctypes.byref(length)):
            return None
        return (ctypes.wstring_at(address.value, length.value).rstrip("\0") if text
                else ctypes.string_at(address.value, length.value))

    translation = query(r"\VarFileInfo\Translation") or b""
    pairs = tuple(struct.iter_unpack("<HH", translation))
    strings = {pair: {key: query(r"\StringFileInfo\{:04X}{:04X}\{}".format(*pair, key), True)
                      for key in VERSION_KEYS} for pair in pairs}
    return {"fixed": query("\\"), "translations": pairs, "strings": strings}


def shell_version(path):
    """Read the same version fields through the independent Windows .NET consumer."""
    script = """
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$fixturePath = [Console]::In.ReadLine()
$fixtureVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($fixturePath)
[pscustomobject]@{
    FileDescription = $fixtureVersion.FileDescription
    ProductName = $fixtureVersion.ProductName
    FileVersion = $fixtureVersion.FileVersion
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        input=str(path) + "\n", encoding="utf-8", stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=30)
    return json.loads(result.stdout.lstrip("\ufeff"))


def executable_content(path):
    """Hash executable code and non-version resources using an independent PE reader."""
    data = Path(path).read_bytes()
    pe = struct.unpack_from("<I", data, 60)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = pe + 24
    table = optional + struct.unpack_from("<H", data, pe + 20)[0]
    sections, code = [], {}
    for index in range(count):
        offset = table + index * 40
        name = data[offset:offset + 8].rstrip(b"\0")
        virtual_size, rva, raw_size, raw = struct.unpack_from("<4I", data, offset + 8)
        flags = struct.unpack_from("<I", data, offset + 36)[0]
        sections.append((rva, max(virtual_size, raw_size), raw))
        if flags & 0x20:
            code[name] = hashlib.sha256(data[raw:raw + raw_size]).hexdigest()

    def file_offset(rva):
        for address, size, raw in sections:
            if address <= rva < address + size:
                return raw + rva - address
        raise ValueError("PE resource points outside mapped sections")

    directories = optional + (112 if struct.unpack_from("<H", data, optional)[0] == 0x20B else 96)
    resource_rva, resource_size = struct.unpack_from("<II", data, directories + 16)
    resources = {}
    if resource_rva and resource_size:
        base = file_offset(resource_rva)

        def walk(relative, ancestors=()):
            offset = base + relative
            named, identifiers = struct.unpack_from("<HH", data, offset + 12)
            for index in range(named + identifiers):
                name, child = struct.unpack_from("<II", data, offset + 16 + index * 8)
                if name & 0x80000000:
                    address = base + (name & 0x7FFFFFFF)
                    length = struct.unpack_from("<H", data, address)[0]
                    name = data[address + 2:address + 2 + length * 2].decode("utf-16-le")
                keys = ancestors + (name,)
                if keys[0] == 16:
                    continue
                if child & 0x80000000:
                    walk(child & 0x7FFFFFFF, keys)
                else:
                    rva, length = struct.unpack_from("<II", data, base + child)
                    raw = file_offset(rva)
                    resources[keys] = hashlib.sha256(data[raw:raw + length]).hexdigest()

        walk(0)
    return code, resources


class DisplayNameFormatterTests(unittest.TestCase):
    def test_terminal_extension_and_each_ascii_capital_are_formatted_literally(self):
        examples = {
            "RemoDwAgentAcess.exe": "Remo Dw Agent Acess",
            "RemoDwAgent": "Remo Dw Agent",
            "RemoDw.EXE": "Remo Dw",
            "A.exe": "A",
            "ABC.exe": "A B C",
            "CPUAgent.eXe": "C P U Agent",
            "lowercase.exe": "lowercase",
            "Already Spaced.exe": "Already Spaced",
            "Remo  Dw.exe": "Remo  Dw",
            "AgentV2.exe": "Agent V2",
            "1Agent.exe": "1 Agent",
            "RemoAgent1Svc.exe": "Remo Agent1 Svc",
            "Remo_Dw-Agent.exe": "Remo_ Dw- Agent",
            "setup.exe.exe": "setup.exe",
        }
        for value, expected in examples.items():
            with self.subTest(value=value):
                self.assertEqual(setup_version.format_display_name(value), expected)

    def test_invalid_names_and_empty_stem_are_rejected(self):
        for value in (None, "", "   ", ".exe", "A\nB", "A\0B"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                setup_version.format_display_name(value)

    def test_valid_maximum_filename_and_service_names_expand_without_truncation(self):
        filename = "A" * 64 + ".exe"
        label = setup_version.format_display_name(filename)
        self.assertEqual(label, " ".join("A" * 64))
        self.assertEqual(len(label), 127)
        service_label = setup_version.format_display_name("A" * 100)
        self.assertEqual(len(service_label), 199)
        with self.assertRaises(ValueError):
            setup_version.format_display_name("A" * 101)


@unittest.skipUnless(os.name == "nt" and NATIVE.is_file() and RUNTIME.is_file(),
                     "Windows and the existing read-only native/runtime fixtures are required")
class ProcessDescriptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def copy_fixture(self, source, name):
        destination = self.directory / name
        shutil.copy2(source, destination)
        return destination

    def assert_labels(self, path, description, product=None):
        version = windows_version(path)
        self.assertTrue(version["translations"])
        for strings in version["strings"].values():
            self.assertEqual(strings["FileDescription"], description)
            self.assertEqual(strings["ProductName"], description if product is None else product)
        return version

    def installed_profile(self, profile, from_filename=False):
        (self.directory / "runtime").mkdir()
        (self.directory / "native").mkdir()
        shutil.copy2(RUNTIME, self.directory / "runtime" / "dwagent.exe")
        shutil.copy2(NATIVE, self.directory / "native" / "dwagsvc.exe")
        setup = fixtures.support_setup.SupportInstall()
        setup._options = {"server_install_identity": True, "install_identity_version": 2,
                          "dynamic_process_description": True}
        if from_filename:
            setup._options["process_description_from_filename"] = True
        setup._setup_authorized = True
        setup._apply_install_identity(profile)
        setup._install_path.set(str(self.directory))
        setup._native.set_install_path(str(self.directory))
        with patch.object(fixtures.installer.Install, "copy_runtime"), \
                patch.object(fixtures.installer.Install, "copy_native"):
            setup.copy_runtime(0, 1)
            setup.copy_native(0, 1)
        return setup

    def test_native_gets_a_friendly_name_and_keeps_code(self):
        original = NATIVE.read_bytes()
        target = self.copy_fixture(NATIVE, "fixture-service.exe")
        contents = executable_content(target)
        setup_version.set_executable_description(target, "Remo Dw")
        self.assert_labels(target, "Remo Dw")
        self.assertEqual(executable_content(target), contents)
        self.assertEqual(NATIVE.read_bytes(), original)

    def test_python_preserves_versions_copyright_code_icons_and_manifest(self):
        original = RUNTIME.read_bytes()
        target = self.copy_fixture(RUNTIME, "fixture-agent.exe")
        before, contents = windows_version(target), executable_content(target)
        self.assertTrue(before["fixed"])
        self.assertTrue(contents[0])
        self.assertTrue(contents[1])
        setup_version.set_executable_description(target, "Remo Dw", product_name="Remo Support")
        after = self.assert_labels(target, "Remo Dw", "Remo Support")
        self.assertEqual(after["fixed"], before["fixed"])
        self.assertEqual(after["translations"], before["translations"])
        for pair, strings in before["strings"].items():
            for key in VERSION_KEYS[2:]:
                self.assertEqual(after["strings"][pair][key], strings[key], key)
        self.assertEqual(executable_content(target), contents)
        self.assertEqual(RUNTIME.read_bytes(), original)

    def test_changing_the_name_again_replaces_old_labels_and_preserves_code(self):
        target = self.copy_fixture(RUNTIME, "fixture-agent.exe")
        contents = executable_content(target)
        setup_version.set_executable_description(target, "Remo Dw")
        setup_version.set_executable_description(target, "Fixture Support \u03a9")
        self.assert_labels(target, "Fixture Support \u03a9")
        self.assertEqual(executable_content(target), contents)

    def test_locked_executable_failure_preserves_every_original_byte(self):
        target = self.copy_fixture(RUNTIME, "fixture-locked.exe")
        original = target.read_bytes()
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        api.CreateFileW.restype = wintypes.HANDLE
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        handle = api.CreateFileW(str(target), 0x80000000, 1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            with self.assertRaises(OSError):
                setup_version.set_executable_description(target, "Should Not Be Written")
            self.assertEqual(target.read_bytes(), original)
        finally:
            api.CloseHandle(handle)

    def test_invalid_pe_failure_leaves_source_unchanged(self):
        target = self.directory / "invalid.exe"
        original = b"This is an ordinary fixture, not an executable."
        target.write_bytes(original)
        with self.assertRaises(OSError):
            setup_version.set_executable_description(target, "Remo Dw")
        self.assertEqual(target.read_bytes(), original)

    def test_failed_staging_write_preserves_original_and_cleans_temporary_file(self):
        target = self.copy_fixture(RUNTIME, "fixture-atomic.exe")
        original = target.read_bytes()
        siblings = {path.name for path in self.directory.iterdir()}

        def corrupt_staging(path, resources):
            staging = Path(path)
            self.assertNotEqual(staging, target)
            self.assertEqual(staging.parent, target.parent)
            staging.write_bytes(b"fixture partially written staging file")
            raise OSError("fixture resource transaction failed")

        with patch.object(setup_version._WindowsResources, "write", side_effect=corrupt_staging):
            with self.assertRaisesRegex(OSError, "fixture resource transaction failed"):
                setup_version.set_executable_description(target, "Remo Dw")
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual({path.name for path in self.directory.iterdir()}, siblings)

    def test_installer_names_both_selected_executables_from_authorized_display_name(self):
        profile = {"main_executable": "RemoDw.exe", "service_executable": "RemoDw.exe",
                   "service_name": "RemoDw", "service_display_name": "Legacy Portal Display"}
        self.installed_profile(profile)
        for directory, key in (("runtime", "main_executable"), ("native", "service_executable")):
            self.assert_labels(self.directory / directory / profile[key], "Legacy Portal Display")
        self.assertFalse((self.directory / "runtime" / "dwagent.exe").exists())
        self.assertFalse((self.directory / "native" / "dwagsvc.exe").exists())

    def test_filename_source_matches_exact_requested_names_and_formats_services_properties(self):
        profile = {"main_executable": "RemoDwAgentAcess.exe", "service_executable": "RemoDwAgentAcess.exe",
                   "service_name": "RemoDwAgent", "service_display_name": "RemoDwAgent"}
        setup = self.installed_profile(profile, from_filename=True)
        for directory, key in (("runtime", "main_executable"), ("native", "service_executable")):
            target = self.directory / directory / profile[key]
            self.assert_labels(target, "Remo Dw Agent Acess")
            shell = shell_version(target)
            self.assertEqual(shell["FileDescription"], "Remo Dw Agent Acess")
            self.assertEqual(shell["ProductName"], "Remo Dw Agent Acess")
        setup._native.prepare_file()
        properties = dict(line.split("=", 1) for line in
            (self.directory / "native" / "service.properties").read_text(encoding="utf-8").splitlines()
            if "=" in line)
        self.assertEqual(properties["serviceDisplayName"], "Remo Dw Agent")
        self.assertEqual(properties["serviceName"], "RemoDwAgent")
        self.assertEqual(properties["pythonPath"], str(self.directory / "runtime" / profile["main_executable"]))
        self.assertEqual(setup._options["install_identity"], profile)
        self.assertEqual(setup._native.get_service_display_name(), "Remo Dw Agent")

    def test_different_executable_filenames_produce_their_own_display_names(self):
        profile = {"main_executable": "RemoMainAgent.exe", "service_executable": "RemoServiceAgent.exe",
                   "service_name": "RemoDwAgent", "service_display_name": "RemoDwAgent"}
        self.installed_profile(profile, from_filename=True)
        self.assert_labels(self.directory / "runtime" / profile["main_executable"], "Remo Main Agent")
        self.assert_labels(self.directory / "native" / profile["service_executable"], "Remo Service Agent")

    def test_filename_labels_longer_than_100_characters_are_installed_without_truncation(self):
        profile = {"main_executable": "A" * 64 + ".exe", "service_executable": "A" * 64 + ".exe",
                   "service_name": "LongLabelFixture", "service_display_name": "A" * 100}
        setup = self.installed_profile(profile, from_filename=True)
        label = " ".join("A" * 64)
        self.assertGreater(len(label), 100)
        self.assert_labels(self.directory / "runtime" / profile["main_executable"], label)
        self.assert_labels(self.directory / "native" / profile["service_executable"], label)
        setup._native.prepare_file()
        self.assertEqual(setup._native.get_service_display_name(), " ".join("A" * 100))

    def test_filename_formatting_mode_and_raw_identity_survive_uninstaller_loading(self):
        profile = {"main_executable": "RemoDwAgentAcess.exe", "service_executable": "RemoDwAgentAcess.exe",
                   "service_name": "RemoDwAgent", "service_display_name": "RemoDwAgent"}
        setup = self.installed_profile(profile, from_filename=True)
        config = json.loads((fixtures.ROOT / "os_win_installer" /
            "install-dynamic-10443-v2.json").read_text(encoding="utf-8"))
        setup._options["remote_password"] = config["remote_password"]
        with patch.object(fixtures.installer.Install, "_download_files"):
            setup._download_files(0, 1)
        access = json.loads((self.directory / "setup-access.json").read_text(encoding="utf-8"))
        self.assertEqual(access["install_identity"], profile)
        self.assertIs(access["process_description_from_filename"], True)
        self.assertEqual(access["remote_password"], config["remote_password"])
        uninstaller = fixtures.support_setup.SupportUninstall()
        with patch.object(fixtures.support_setup, "__file__", str(self.directory / "support_setup.py")):
            uninstaller._load_access_config()
        self.assertEqual(uninstaller._native.get_service_display_name(), "Remo Dw Agent")
        self.assertEqual(uninstaller._native._name, "RemoDwAgent")
        self.assertEqual(uninstaller._native._runtime, "RemoDwAgentAcess.exe")
        self.assertEqual(uninstaller._native._service_executable, "RemoDwAgentAcess.exe")
        self.assertEqual(uninstaller._access_config["install_identity"], profile)

    def test_windows_shell_dotnet_reads_friendly_names_on_both_real_executables(self):
        # Windows shell consumers use FileVersionInfo; VerQueryValue alone misses
        # malformed new resources that expose strings but omit FileVersion.
        for source, name in ((NATIVE, "shell-native.exe"), (RUNTIME, "shell-runtime.exe")):
            with self.subTest(executable=name):
                target = self.copy_fixture(source, name)
                setup_version.set_executable_description(target, "Remo Dw")
                version = shell_version(target)
                self.assertEqual(version["FileDescription"], "Remo Dw")
                self.assertEqual(version["ProductName"], "Remo Dw")
                self.assertTrue(version["FileVersion"])


if __name__ == "__main__":
    unittest.main()
