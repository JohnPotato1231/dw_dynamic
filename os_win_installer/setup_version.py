"""Set friendly process names on the installer's copied Windows executables.

VERSIONINFO FileDescription and ProductName strings are changed; missing version
strings are filled from the fixed version so Windows selects the correct table.
Existing fixed versions, nonempty version strings, translations and unrelated PE
resources are retained.  Changing a signed executable's resources invalidates its original
Authenticode signature; this module does not sign files or change their signer.

The pure ``update_version_info`` function is also usable on non-Windows hosts.
Actual executable updates use the Windows resource update transaction APIs.
"""

import ctypes
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tempfile


_RT_VERSION = 16
_DEFAULT_LANGUAGE = 0x0409
_UNICODE_CODEPAGE = 1200
_MAX_BLOCK_LENGTH = 0xFFFF
_MAX_DISPLAY_LENGTH = 200


class _Block:
    def __init__(self, key, value_type=1, value=b"", children=None):
        self.key = key
        self.value_type = value_type
        self.value = value
        self.children = list(children or ())


def _aligned(position):
    return (position + 3) & ~3


def _parse_block(data, start=0, limit=None, depth=0):
    if limit is None:
        limit = len(data)
    if depth > 32 or start + 6 > limit:
        raise ValueError("Executable version metadata contains a truncated block.")
    length, value_length, value_type = struct.unpack_from("<HHH", data, start)
    end = start + length
    if length < 8 or end > limit:
        raise ValueError("Executable version metadata has an invalid block length.")
    position = start + 6
    key_start = position
    while position + 2 <= end and data[position:position + 2] != b"\0\0":
        position += 2
    if position + 2 > end:
        raise ValueError("Executable version metadata contains an unterminated key.")
    try:
        key = data[key_start:position].decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise ValueError("Executable version metadata contains an invalid key.") from error
    position = _aligned(position + 2)
    byte_length = value_length * 2 if value_type == 1 else value_length
    if not byte_length and position > end:
        position = end
    if position + byte_length > end:
        raise ValueError("Executable version metadata contains a truncated value.")
    value = data[position:position + byte_length]
    position = min(_aligned(position + byte_length), end)
    children = []
    while position < end:
        # Some resource writers retain zero padding at the end of a container.
        if not any(data[position:end]):
            break
        child, child_end = _parse_block(data, position, end, depth + 1)
        children.append(child)
        position = min(_aligned(child_end), end)
    return _Block(key, value_type, value, children), end


def _serialize_block(block):
    if "\0" in block.key:
        raise ValueError("Executable version metadata contains an invalid key.")
    if block.value_type == 1 and len(block.value) % 2:
        raise ValueError("Executable version metadata contains an invalid text value.")
    value_length = (len(block.value) // 2 if block.value_type == 1
                    else len(block.value))
    result = bytearray(b"\0" * 6)
    result.extend(block.key.encode("utf-16-le") + b"\0\0")
    result.extend(b"\0" * (_aligned(len(result)) - len(result)))
    result.extend(block.value)
    for child in block.children:
        result.extend(b"\0" * (_aligned(len(result)) - len(result)))
        result.extend(_serialize_block(child))
    if len(result) > _MAX_BLOCK_LENGTH or value_length > _MAX_BLOCK_LENGTH:
        raise ValueError("Executable version metadata exceeds the Windows size limit.")
    struct.pack_into("<HHH", result, 0, len(result), value_length, block.value_type)
    return bytes(result)


def _validate_label(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= _MAX_DISPLAY_LENGTH
            or value != value.strip() or not value.isprintable()):
        raise ValueError("Process display names must contain 1-200 printable characters "
                         "without surrounding spaces.")
    return value


def format_display_name(value):
    """Remove a terminal .exe and space each capital after the first character.

    This is a literal capital-letter rule, including consecutive capitals:
    ExampleClientTool.exe becomes Example Client Tool, and ABC becomes A B C.
    Existing spaces are retained without inserting another space before a capital.
    The caller keeps the original filename or service identifier unchanged.
    """
    value = _validate_label(value)
    if value.lower().endswith(".exe"):
        value = value[:-4]
    return _validate_label(re.sub(r"(?<!^)(?<!\s)([A-Z])", r" \1", value))


def _translation_pairs(root):
    pairs = []
    for variable_info in root.children:
        if variable_info.key != "VarFileInfo":
            continue
        for translation in variable_info.children:
            if translation.key != "Translation":
                continue
            if len(translation.value) % 4:
                raise ValueError("Executable version metadata has an invalid translation list.")
            for pair in struct.iter_unpack("<HH", translation.value):
                if pair not in pairs:
                    pairs.append(pair)
    return pairs


def _set_string(table, key, value):
    encoded = value.encode("utf-16-le") + b"\0\0"
    matching = [item for item in table.children if item.key.casefold() == key.casefold()]
    if not matching:
        table.children.append(_Block(key, 1, encoded))
    for item in matching:
        item.value_type = 1
        item.value = encoded


def _fixed_version_strings(value):
    if len(value) < 24 or struct.unpack_from("<I", value)[0] != 0xFEEF04BD:
        return "0.0.0.0", "0.0.0.0"
    numbers = struct.unpack_from("<4I", value, 8)
    return tuple("{}.{}.{}.{}".format(high >> 16, high & 0xFFFF,
                                     low >> 16, low & 0xFFFF)
                 for high, low in ((numbers[0], numbers[1]), (numbers[2], numbers[3])))


def _ensure_version_string(table, key, default):
    matching = [item for item in table.children if item.key.casefold() == key.casefold()]
    if not matching:
        _set_string(table, key, default)
        return
    for item in matching:
        if not item.value or item.value[:2] == b"\0\0":
            item.value_type = 1
            item.value = default.encode("utf-16-le") + b"\0\0"


def update_version_info(data, description, product_name=None, language=_DEFAULT_LANGUAGE):
    """Return a VERSIONINFO blob with the requested labels in every string table.

    ``data=None`` creates a standard version resource for an executable that has
    none.  The language is a Windows LANGID, used only when a new string table is
    needed.  Existing nonempty version strings and other metadata values are copied
    without changing them.  Missing/empty version strings use the fixed versions.
    """
    description = _validate_label(description)
    product_name = _validate_label(description if product_name is None else product_name)
    if not isinstance(language, int) or not 0 <= language <= 0xFFFF:
        raise ValueError("Executable version metadata has an invalid language identifier.")
    if data is None:
        # VS_FIXEDFILEINFO: an unsigned application without an asserted version.
        fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, 0, 0, 0, 0,
                            0x3F, 0, 0x00040004, 1, 0, 0, 0)
        root = _Block("VS_VERSION_INFO", 0, fixed)
        trailing = b""
    else:
        if not isinstance(data, bytes):
            raise TypeError("Executable version metadata must be bytes or None.")
        root, end = _parse_block(data)
        if root.key != "VS_VERSION_INFO" or root.value_type != 0:
            raise ValueError("Executable has an unsupported version resource.")
        trailing = data[end:]
    translations = _translation_pairs(root)
    string_info = [item for item in root.children if item.key == "StringFileInfo"]
    tables = [table for container in string_info for table in container.children
              if re.fullmatch(r"[0-9a-fA-F]{8}", table.key)]
    if not tables:
        if not string_info:
            string_info.append(_Block("StringFileInfo"))
            root.children.append(string_info[0])
        for table_language, codepage in translations or [(language or _DEFAULT_LANGUAGE,
                                                         _UNICODE_CODEPAGE)]:
            table = _Block("{:04X}{:04X}".format(table_language, codepage))
            string_info[0].children.append(table)
            tables.append(table)
    file_version, product_version = _fixed_version_strings(root.value)
    for table in tables:
        _set_string(table, "FileDescription", description)
        _set_string(table, "ProductName", product_name)
        # .NET FileVersionInfo and Explorer use FileVersion to decide whether a
        # language/codepage table matched.  Without it, fallback queries can erase
        # otherwise valid description strings from a newly created native table.
        _ensure_version_string(table, "FileVersion", file_version)
        _ensure_version_string(table, "ProductVersion", product_version)
    if not translations:
        pairs = []
        for table in tables:
            pair = (int(table.key[:4], 16), int(table.key[4:], 16))
            if pair not in pairs:
                pairs.append(pair)
        variable_info = next((item for item in root.children if item.key == "VarFileInfo"), None)
        if variable_info is None:
            variable_info = _Block("VarFileInfo")
            root.children.append(variable_info)
        translation = next((item for item in variable_info.children
                            if item.key == "Translation"), None)
        encoded = b"".join(struct.pack("<HH", *pair) for pair in pairs)
        if translation is None:
            variable_info.children.append(_Block("Translation", 0, encoded))
        else:
            translation.value_type = 0
            translation.value = encoded
    return _serialize_block(root) + trailing


def _windows_error(action, path, code):
    detail = ctypes.FormatError(code).strip()
    advice = ""
    if code == 5:
        advice = " Retry the installer as administrator and check the folder permissions."
    elif code in (32, 33):
        advice = " Close programs using this executable and retry the installer."
    error = OSError(code, "{} (Windows error {}: {}).{}".format(
        action, code, detail, advice), str(path))
    error.winerror = code
    return error


class _WindowsResources:
    def __init__(self):
        from ctypes import wintypes

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.name_callback = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_ssize_t)
        self.language_callback = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.WORD, ctypes.c_ssize_t)
        functions = {
            "LoadLibraryExW": ([wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD], wintypes.HMODULE),
            "FreeLibrary": ([wintypes.HMODULE], wintypes.BOOL),
            "EnumResourceNamesW": ([wintypes.HMODULE, ctypes.c_void_p, self.name_callback,
                                     ctypes.c_ssize_t], wintypes.BOOL),
            "EnumResourceLanguagesW": ([wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p,
                                         self.language_callback, ctypes.c_ssize_t], wintypes.BOOL),
            "FindResourceExW": ([wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p,
                                  wintypes.WORD], wintypes.HRSRC),
            "SizeofResource": ([wintypes.HMODULE, wintypes.HRSRC], wintypes.DWORD),
            "LoadResource": ([wintypes.HMODULE, wintypes.HRSRC], wintypes.HGLOBAL),
            "LockResource": ([wintypes.HGLOBAL], ctypes.c_void_p),
            "BeginUpdateResourceW": ([wintypes.LPCWSTR, wintypes.BOOL], wintypes.HANDLE),
            "UpdateResourceW": ([wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   wintypes.WORD, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "EndUpdateResourceW": ([wintypes.HANDLE, wintypes.BOOL], wintypes.BOOL),
        }
        for name, (arguments, result) in functions.items():
            function = getattr(self.kernel, name)
            function.argtypes = arguments
            function.restype = result

    @staticmethod
    def _name_pointer(name):
        if isinstance(name, int):
            return ctypes.c_void_p(name)
        return ctypes.cast(ctypes.c_wchar_p(name), ctypes.c_void_p)

    def read(self, path):
        # DATAFILE | IMAGE_RESOURCE maps resources without executing entry points.
        module = self.kernel.LoadLibraryExW(str(path), None, 0x00000002 | 0x00000020)
        if not module:
            raise _windows_error("Could not read executable metadata", path, ctypes.get_last_error())
        try:
            names = []

            @self.name_callback
            def collect_name(handle, resource_type, name, parameter):
                names.append((name or 0) if not name or name <= 0xFFFF
                             else ctypes.wstring_at(name))
                return True

            ctypes.set_last_error(0)
            if not self.kernel.EnumResourceNamesW(module, _RT_VERSION, collect_name, 0):
                code = ctypes.get_last_error()
                if code in (1812, 1813):  # No resources, or no VERSIONINFO type.
                    return []
                raise _windows_error("Could not enumerate executable metadata", path, code)
            resources = []
            for name in names:
                languages = []

                @self.language_callback
                def collect_language(handle, resource_type, resource_name, language, parameter):
                    languages.append(language)
                    return True

                name_pointer = self._name_pointer(name)
                if not self.kernel.EnumResourceLanguagesW(
                        module, _RT_VERSION, name_pointer, collect_language, 0):
                    raise _windows_error("Could not enumerate executable metadata languages",
                                         path, ctypes.get_last_error())
                for language in languages:
                    resource = self.kernel.FindResourceExW(module, _RT_VERSION, name_pointer, language)
                    if not resource:
                        raise _windows_error("Could not locate executable metadata", path,
                                             ctypes.get_last_error())
                    size = self.kernel.SizeofResource(module, resource)
                    if not size:
                        raise _windows_error("Could not read executable metadata size", path,
                                             ctypes.get_last_error())
                    loaded = self.kernel.LoadResource(module, resource)
                    pointer = self.kernel.LockResource(loaded) if loaded else None
                    if not pointer:
                        raise _windows_error("Could not load executable metadata", path,
                                             ctypes.get_last_error())
                    resources.append((name, language, ctypes.string_at(pointer, size)))
            return resources
        finally:
            if not self.kernel.FreeLibrary(module):
                raise _windows_error("Could not release executable metadata", path,
                                     ctypes.get_last_error())

    def write(self, path, resources):
        transaction = self.kernel.BeginUpdateResourceW(str(path), False)
        if not transaction:
            raise _windows_error("Could not open executable metadata for update", path,
                                 ctypes.get_last_error())
        committed = False
        try:
            for name, language, data in resources:
                buffer = ctypes.create_string_buffer(data)
                if not self.kernel.UpdateResourceW(
                        transaction, _RT_VERSION, self._name_pointer(name), language,
                        ctypes.cast(buffer, ctypes.c_void_p), len(data)):
                    raise _windows_error("Could not update the executable process name", path,
                                         ctypes.get_last_error())
            if not self.kernel.EndUpdateResourceW(transaction, False):
                raise _windows_error("Could not save the executable process name", path,
                                     ctypes.get_last_error())
            committed = True
        finally:
            if not committed:
                # Discard queued changes on every failure.  EndUpdateResource may
                # already have released the handle when its commit call failed.
                self.kernel.EndUpdateResourceW(transaction, True)


def set_executable_description(executable, description, product_name=None):
    """Update only the supplied install copy, before that executable is started.

    Every existing VERSIONINFO resource name/language is updated in one Windows
    resource transaction on a private sibling copy, followed by atomic replace.
    A missing VERSIONINFO resource is created as ID 1.  Validation and serialization
    complete before staging; any resource-update failure leaves the original file
    untouched.  The customized copy gets a fresh modification time.
    """
    description = _validate_label(description)
    product_name = _validate_label(description if product_name is None else product_name)
    if os.name != "nt":
        raise OSError("Setting executable process names requires Windows.")
    path = Path(os.path.abspath(os.fspath(executable)))
    information = path.lstat()
    if (not stat.S_ISREG(information.st_mode) or path.is_symlink()
            or getattr(information, "st_file_attributes", 0) & 0x400):
        raise ValueError("The process name can only be set on a regular executable install copy.")
    if information.st_nlink > 1:
        raise ValueError("The executable install copy must not share hard links with other files.")
    resources = _WindowsResources()
    existing = resources.read(path)
    changes = [(name, language, update_version_info(data, description, product_name, language))
               for name, language, data in existing]
    if not changes:
        changes = [(1, _DEFAULT_LANGUAGE,
                    update_version_info(None, description, product_name, _DEFAULT_LANGUAGE))]
    original_identity = (information.st_dev, information.st_ino,
                         information.st_size, information.st_mtime_ns)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".dwlabel-", suffix=".exe",
                                                  dir=str(path.parent))
    temporary = Path(temporary_name)
    failed = False
    try:
        os.close(descriptor)
        # Copy bytes only: staging must stay writable until resource changes commit.
        shutil.copyfile(str(path), str(temporary))
        resources.write(temporary, changes)
        current = path.lstat()
        current_identity = (current.st_dev, current.st_ino,
                            current.st_size, current.st_mtime_ns)
        if (current_identity != original_identity or not stat.S_ISREG(current.st_mode)
                or current.st_nlink > 1
                or getattr(current, "st_file_attributes", 0) & 0x400):
            raise OSError("The executable changed during its process-name update. "
                          "Close other installers and retry.")
        shutil.copymode(str(path), str(temporary), follow_symlinks=False)
        os.utime(str(temporary), None)
        try:
            os.replace(str(temporary), str(path))
        except OSError as error:
            if getattr(error, "winerror", None):
                raise _windows_error("Could not replace the executable with its updated process name",
                                     path, error.winerror) from error
            raise
    except BaseException:
        failed = True
        raise
    finally:
        try:
            try:
                temporary.unlink()
            except PermissionError:
                os.chmod(str(temporary), stat.S_IREAD | stat.S_IWRITE)
                temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            if not failed:
                raise
