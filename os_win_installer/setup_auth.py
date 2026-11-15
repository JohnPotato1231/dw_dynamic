"""Password verification shared by setup and the normal uninstaller."""

import hashlib
import hmac
import http.client
import json
import ntpath
import re
import secrets
import socket
import ssl
from urllib.parse import urlsplit


# This shared client credential gates profile retrieval, not the user-entered P.
# A distributed client cannot keep a hardcoded credential permanently secret.
_INSTALL_IDENTITY_CLIENT_PASSWORD = "93199319"


DEFAULT_INSTALL_IDENTITY = {
    "main_executable": "dwagent.exe",
    "service_executable": "dwagsvc.exe",
    "service_name": "DWAgent",
    "service_display_name": "DWAgent",
}

DEFAULT_INSTALL_METADATA = {"install_path": "", "publisher": "DWService"}


def validate_install_path(value):
    """Validate a Windows application directory, including on the Linux portal."""
    if not isinstance(value, str) or len(value) > 180:
        raise ValueError("Installation path must be at most 180 characters.")
    if not value:
        return value
    path = value.replace("/", "\\")
    if path.lower().startswith("%programfiles%\\"):
        path = "C:\\Program Files\\" + path[len("%ProgramFiles%\\"):]
    drive, tail = ntpath.splitdrive(path)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\"):
        raise ValueError("Use an absolute local application path or %ProgramFiles%\\Application.")
    parts = tail[1:].split("\\")
    if (not parts or any(not part or part in (".", "..") or part.endswith((".", " "))
                         or re.search(r'[<>:"/\\|?*%\x00-\x1f\x7f]', part)
                         or re.fullmatch(r"(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?", part, re.I)
                         for part in parts)
            or parts[0].lower() in {"windows", "winnt", "system volume information", "$recycle.bin"}
            or (len(parts) == 1 and parts[0].lower() in {"program files", "program files (x86)", "programdata", "users"})):
        raise ValueError("Choose a new application subfolder outside Windows system directories.")
    return value


def validate_install_identity(value):
    """Accept only plain filenames and names safe for Windows properties files."""
    if (not isinstance(value, dict) or not set(DEFAULT_INSTALL_IDENTITY).issubset(value)
            or set(value) - set(DEFAULT_INSTALL_IDENTITY) - set(DEFAULT_INSTALL_METADATA)):
        raise ValueError("Invalid installation naming settings.")
    for key in ("main_executable", "service_executable"):
        name = value[key]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}\.exe", name, re.I):
            raise ValueError("Executable names must be plain .exe filenames.")
        stem = name[:-4].lower()
        if stem in {"con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[0-9]", stem):
            raise ValueError("That executable filename is reserved by Windows.")
    if value["service_executable"].lower() in {"dwaglnc.exe", "dwagupd.exe"}:
        raise ValueError("The service filename conflicts with another agent component.")
    if not isinstance(value["service_name"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,79}", value["service_name"]):
        raise ValueError("Service names must use letters, digits, underscores or hyphens.")
    if value["service_name"].lower() in {"con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[0-9]", value["service_name"], re.I):
        raise ValueError("The service name is reserved by Windows.")
    if not isinstance(value["service_display_name"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _().-]{0,99}", value["service_display_name"]):
        raise ValueError("Enter a display name of 1-100 plain text characters.")
    if "install_path" in value:
        validate_install_path(value["install_path"])
    if "publisher" in value:
        publisher = value["publisher"]
        if (not isinstance(publisher, str) or not 1 <= len(publisher) <= 100
                or publisher != publisher.strip() or not publisher.isprintable()):
            raise ValueError("Publisher must be 1-100 printable characters without surrounding spaces.")
    return dict(value)


class PasswordServerUnavailable(Exception):
    """The password server could not securely authorize this operation."""


def valid_remote_password(record):
    try:
        endpoint = urlsplit(record["url"])
        return (endpoint.scheme == "https" and bool(endpoint.hostname)
                and endpoint.path == "/api/verify" and not endpoint.query
                and not endpoint.fragment and not endpoint.username
                and not endpoint.password and endpoint.port in (None, 443, 10443)
                and isinstance(record["ca_pem"], str)
                and len(record["ca_pem"]) < 65536
                and "-----BEGIN CERTIFICATE-----" in record["ca_pem"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def valid_access_config(options):
    if not isinstance(options, dict):
        return False
    if "remote_password" in options:
        return (valid_remote_password(options["remote_password"])
                and ("recovery_password" not in options
                     or valid_password_record(options["recovery_password"])))
    return valid_password_record(options.get("setup_password"))


def _local_device_name():
    """Keep optional device reporting from affecting password verification."""
    try:
        hostname = socket.gethostname()
        return hostname[:255] if isinstance(hostname, str) else ""
    except Exception:
        return ""


def verify_access_password(password, options, *, install_identity=None):
    """Accept an explicitly configured recovery hash OR server authorization."""
    if install_identity is not None:
        install_identity.clear()
    if "remote_password" not in options:
        return verify_password(password, options.get("setup_password"))
    record = options["remote_password"]
    if not valid_remote_password(record):
        raise PasswordServerUnavailable("The password server configuration is invalid.")
    if not isinstance(password, str) or not password or len(password) > 1024:
        return False
    if "recovery_password" in options:
        recovery = options["recovery_password"]
        if not valid_password_record(recovery):
            raise PasswordServerUnavailable("The local recovery password configuration is invalid.")
        # Check locally first so recovery still works without an internet connection.
        # Only the salted hash is bundled; never send the recovery password online.
        if verify_password(password, recovery):
            return True
    connection = None
    try:
        endpoint = urlsplit(record["url"])
        context = ssl.create_default_context(cadata=record["ca_pem"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
                                                  timeout=8, context=context)
        request = {"password": password, "device_name": _local_device_name()}
        if install_identity is not None:
            request["include_install_identity"] = True
            if options.get("install_identity_version") == 2:
                request["install_identity_version"] = 2
        body = json.dumps(request).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if install_identity is not None:
            headers["Authorization"] = "Bearer " + _INSTALL_IDENTITY_CLIENT_PASSWORD
        connection.request("POST", endpoint.path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status == 401:
            raise PasswordServerUnavailable(
                "This installer is not authorized to request installation names. Use an updated installer.")
        if response.status == 403:
            return False
        if response.status == 429:
            raise PasswordServerUnavailable("Too many password attempts. Wait a few minutes and retry.")
        payload = response.read(4097)
        if response.status != 200 or len(payload) > 4096:
            raise ValueError("Unexpected password server response")
        result = json.loads(payload)
        if not isinstance(result, dict) or type(result.get("allowed")) is not bool:
            raise ValueError("Invalid password server response")
        if result["allowed"] and install_identity is not None and "install_identity" in result:
            install_identity.update(validate_install_identity(result["install_identity"]))
        return result["allowed"]
    except PasswordServerUnavailable:
        raise
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise PasswordServerUnavailable(
            "Cannot securely contact the password server. Check your internet connection and retry.") from error
    finally:
        if connection is not None:
            connection.close()


def make_password_record(password):
    if not isinstance(password, str) or not password:
        raise ValueError("A setup password is required.")
    salt = secrets.token_bytes(16)
    iterations = 600000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"algorithm": "pbkdf2-sha256", "iterations": iterations,
            "salt": salt.hex(), "digest": digest.hex()}


def valid_password_record(record):
    try:
        return (isinstance(record, dict)
                and record["algorithm"] == "pbkdf2-sha256"
                and type(record["iterations"]) is int
                and 100000 <= record["iterations"] <= 2000000
                and len(bytes.fromhex(record["salt"])) == 16
                and len(bytes.fromhex(record["digest"])) == 32)
    except (KeyError, TypeError, ValueError):
        return False


def verify_password(password, record):
    if not isinstance(password, str) or not valid_password_record(record):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(record["salt"]), record["iterations"])
    return hmac.compare_digest(actual, bytes.fromhex(record["digest"]))
