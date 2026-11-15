"""Conservative Windows directory checks for authenticated installation repair."""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import stat
import time


_WRITE_ACCESS = (0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100 |
                 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000)
_INHERIT_ONLY = 0x08
_REPARSE_POINT = 0x400


def validate_directory_acl(owner_sid, aces, trusted_sids):
    """Reject writable untrusted ownership/ACEs; tuples are type, flags, mask, SID."""
    trusted = set(trusted_sids)
    if owner_sid not in trusted or aces is None:
        raise ValueError("The installation folder has an untrusted owner or permissions.")
    for ace_type, flags, mask, sid in aces:
        if flags & _INHERIT_ONLY:
            continue
        if ace_type not in (0, 1):  # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE
            raise ValueError("The installation folder has unsupported permissions.")
        if ace_type == 0 and mask & _WRITE_ACCESS and sid not in trusted:
            raise ValueError("The installation folder allows changes by an untrusted account.")


def verify_no_reparse_points(path, recursive=False):
    """Check existing ancestors and, optionally, every descendant without following links."""
    target = Path(os.path.abspath(str(path)))

    def check(candidate):
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & _REPARSE_POINT:
            raise ValueError("The installation folder cannot contain junctions or symbolic links.")
        return details

    for ancestor in (target,) + tuple(target.parents):
        check(ancestor)
    if recursive:
        pending = [target]
        while pending:
            directory = pending.pop()
            details = check(directory)
            if details is None or not stat.S_ISDIR(details.st_mode):
                raise ValueError("The installation folder must be an existing directory.")
            with os.scandir(str(directory)) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    child_details = check(child)
                    if child_details is None:
                        raise ValueError("The installation folder changed during verification.")
                    if stat.S_ISDIR(child_details.st_mode):
                        pending.append(child)


def _read_directory_acl(path):
    """Read a Windows owner/DACL. The descriptor and converted SID strings are freed."""
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    api.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)]
    api.GetNamedSecurityInfoW.restype = wintypes.DWORD
    api.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    api.ConvertSidToStringSidW.restype = wintypes.BOOL
    api.LookupAccountNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, pointer,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD)]
    api.LookupAccountNameW.restype = wintypes.BOOL
    api.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    api.GetAce.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer

    def sid_string(sid):
        text = wintypes.LPWSTR()
        if not sid or not api.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, pointer))

    size, domain_size, kind = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    api.LookupAccountNameW(None, "NT SERVICE\\TrustedInstaller", None,
                           ctypes.byref(size), None, ctypes.byref(domain_size), ctypes.byref(kind))
    if ctypes.get_last_error() != 122 or not size.value:
        raise ctypes.WinError(ctypes.get_last_error())
    sid = ctypes.create_string_buffer(size.value)
    domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
    if not api.LookupAccountNameW(None, "NT SERVICE\\TrustedInstaller", sid,
            ctypes.byref(size), domain, ctypes.byref(domain_size), ctypes.byref(kind)):
        raise ctypes.WinError(ctypes.get_last_error())
    trusted = {"S-1-5-18", "S-1-5-32-544", sid_string(ctypes.cast(sid, pointer))}
    owner, dacl, descriptor = pointer(), pointer(), pointer()
    error = api.GetNamedSecurityInfoW(str(path), 1, 1 | 4, ctypes.byref(owner), None,
                                     ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if error:
        raise ctypes.WinError(error)
    try:
        aces = None
        if dacl:
            # ACL header: BYTE revision, BYTE reserved, WORD size, WORD count, WORD reserved.
            count = ctypes.c_ushort.from_address(dacl.value + 4).value
            aces = []
            for index in range(count):
                address = pointer()
                if not api.GetAce(dacl, index, ctypes.byref(address)):
                    raise ctypes.WinError(ctypes.get_last_error())
                ace_type = ctypes.c_ubyte.from_address(address.value).value
                flags = ctypes.c_ubyte.from_address(address.value + 1).value
                if flags & _INHERIT_ONLY or ace_type not in (0, 1):
                    aces.append((ace_type, flags, 0, None))
                else:
                    mask = wintypes.DWORD.from_address(address.value + 4).value
                    aces.append((ace_type, flags, mask, sid_string(pointer(address.value + 8))))
        return sid_string(owner), aces, trusted
    finally:
        kernel.LocalFree(descriptor)


def verify_protected_directory(path):
    """Require a real existing directory writable only by Windows trusted principals."""
    verify_no_reparse_points(path)
    if not Path(path).is_dir():
        raise ValueError("The installation folder must be an existing directory.")
    validate_directory_acl(*_read_directory_acl(path))


def rename_with_retry(source, destination, timeout=5.0):
    """Move a verified folder to an unused sibling, retrying only Windows sharing errors."""
    source, destination = Path(source), Path(destination)
    if os.path.normcase(os.path.abspath(str(source.parent))) != os.path.normcase(os.path.abspath(str(destination.parent))):
        raise ValueError("An installation backup must stay in the same parent folder.")
    verify_no_reparse_points(source, recursive=True)
    verify_no_reparse_points(destination)
    deadline = time.monotonic() + min(max(float(timeout), 0.0), 15.0)
    while True:
        if destination.exists():
            raise FileExistsError("The installation backup folder already exists.")
        try:
            source.rename(destination)
            return destination
        except OSError as error:
            if getattr(error, "winerror", None) not in (5, 32, 33) or time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
