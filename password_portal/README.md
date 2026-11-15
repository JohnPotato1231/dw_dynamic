# REMO password portal

## Isolated 10443 release

The new portal is `https://82.25.46.70:10443/`. It manages both P passwords and
installation names for `dist/DWAgent-dynamic-10443-x64.exe`.
The original API on 443, admin portal on 9443, and other service on 8443 remain
in place. Existing installers keep their original endpoints.

The new portal has its own service (`remo-dynamic-portal.service`), Unix user,
database, certificate, and browser cookie. Its accounts were seeded from a
consistent copy of the existing portal, so the current admin credentials and
P passwords initially work there too. Later password changes on either portal
are independent. Active browser sessions and audit history were not copied.

Both P and the separate built-in installer credential are required before
custom names are returned. The initial server profile uses `remo_dwagent.exe`,
`remo_dwagsvc.exe`, service name `remo_dwagent`, and display name
`REMO Remote Support`. Edit these through Installation names on the new portal.
The new EXE contains DWAgent defaults; these custom names remain on the server.

The installer configuration for this release is
`os_win_installer/install-dynamic-10443.json`; the original `install.json` was
preserved. The new EXE verifies the new server certificate from that configuration.

`deploy_isolated.py` refuses existing deployment paths and never replaces the
original portal. `verify_isolated_live.py` tests only the new instance using a
temporary P and session, then removes those temporary credentials.

## Server-controlled installation names

`dist/DWAgent-client-auth-x64.exe` bundles only the default process names
`dwagent.exe`, `dwagsvc.exe`, and the service name/display name `DWAgent`.
Its `server_install_identity` setting asks the existing password endpoint for
installation names. The portal returns those settings only when it accepts
both the separate built-in installer credential and the submitted user P,
and `include_install_identity` is exactly `true`.
Old clients keep the original `{ "allowed": true }` response format.

The installer sends its built-in credential in an HTTPS Authorization header
only when requesting installation names. The server holds a separate salted
PBKDF2 hash for this credential, outside the portal-managed P records. Changing
P in the portal does not change the built-in credential. Missing or incorrect
installer credentials receive HTTP 401 and no profile; an incorrect P receives
HTTP 403 and no profile. Legacy requests still verify P without returning names.
The client credential is never shown in the portal or written to request logs.
No additional network port is needed. A distributed EXE's built-in credential
can be extracted and reused; this does not establish exclusive EXE identity.

After deploying this portal update, sign in as administrator and use
**Installation names** to set the four values. For example, use
`remo_dwagent.exe`, `remo_dwagsvc.exe`, `remo_dwagent`, and `REMO Remote Support`.
These examples are documentation, not names embedded in the new EXE.
No settings are seeded automatically: a portal without saved names returns
DWAgent defaults until an administrator saves a profile.

Successful local recovery-password checks and successful checks against an
older portal use DWAgent defaults. A rejected password still blocks the
unmodified installer; changing that local check does not make the server
release a profile. A failed or repeated verification clears previously
received names. Server errors or malformed profiles stop setup with an error.

The bootstrap process keeps its default name. Setup renames only the installed
copies and saves their identity in `setup-access.json` for uninstall. Installed
service properties contain the executable path and separate display name.
Portal edits affect future installations, not existing ones. New installs use
`Program Files/<service_name>` and refuse existing directories or services.
The service metadata identifies the publisher as DWService.

This protects retrieval of server settings, not ownership of Windows names.
Names are visible after installation, and someone who knows them can manually
copy them. The portal update does not add remote-access enrollment controls.

Additional checks:

```powershell
python -m unittest discover -s password_portal -p test_install_identity.py -v
python -m unittest discover -s make/tests -p test_server_identity.py -v
```

The portal at `https://13.210.214.189/` controls the password used by
`MyDWagent2-online-x64.exe` for both installation and uninstall. Admin sign-in
uses a separate password. Changing the EXE password applies to the next online
verification, including already installed copies of this connected build.
Older EXEs and installations retain their existing authentication behavior.

The portal has no configured count limit for labelled, active server passwords. Any active
password is accepted. Removing one revokes it on the next password check while
other entries continue to work; it does not disconnect existing remote sessions.
The previous single password is migrated once as "Existing password". Removing
all server entries disables server-password authorization. Duplicate values are
rejected so removing an entry cannot leave the same password active under a
different label. A value that also matches the local recovery password will
continue to work locally; the portal does not control recovery passwords.

The local test build `MyDWagent2-dual-password-x64.exe` additionally bundles a
separate `recovery_password` record (salted PBKDF2-SHA256, 600,000 iterations).
That build accepts either the local recovery password or the server password
for both installation and uninstall. Recovery is checked locally first, so it
works offline and is not sent to the server. The admin portal changes only the
server password. Changing recovery requires rebuilding/distributing the EXE;
previously installed copies retain their saved recovery hash. Neither hashing
nor these installer checks prevent a local administrator from modifying code.

## Behavior

- `POST /api/verify` accepts JSON with a `password` field and an optional
  `device_name` reported by the installer. It returns
  `200 {"allowed": true}` or `403 {"allowed": false}`. It never returns a
  password hash. Requests are rate limited to 30 per IP per 10 minutes.
- A keyed lookup index selects the matching password before PBKDF2 verification,
  so adding passwords does not require hashing every entry on each attempt.
  The lookup key is stored separately as `state.sqlite3.lookup-key` with private
  permissions. Back it up with the database. Legacy entries are indexed lazily
  after a successful password check.
- Passwords use salted PBKDF2-SHA256 with 600,000 iterations. Plaintext
  passwords are neither persisted nor logged.
- The access log records successful and rejected online password checks with
  the source IP and reported device name. Successful checks also show the
  matching active password's label. Labels are visible only in the signed-in
  dashboard, never in verification responses. Device names are self-reported,
  not proof of a device's identity. Clients without this field show `Unknown`.
- Successful and rejected admin sign-ins record the connection's source IP and
  browser/device details from `User-Agent`, visible after signing in. Browsers
  do not expose the computer's hostname. Missing browser details show `Unknown`;
  these details are self-reported and never include the attempted password.
- All dashboard timestamps display in Indian Standard Time (IST, UTC+05:30),
  including audit events, password creation, and the last password update.
  Stored timestamps remain UTC; the display change does not rewrite history.
- The access-log filters match an exact event and password label, with optional
  **From** and **To** dates and times in IST. The selected **To** minute is
  inclusive. Filters apply before the latest-100 limit, so they can find older
  retained records. Label choices include historical labels for revoked
  passwords. **Apply filters** keeps the selections; **Clear** shows all events.
  Invalid dates or a From time later than To show a validation message.
- The dashboard shows the latest 100 matching events. Older records remain stored until
  an administrator uses **Delete logs older than 7 days**. This removes only
  events strictly older than seven days; it preserves newer events, passwords,
  sessions, and rate-limit records. Log cleanup requires a signed-in session,
  a valid CSRF token, and the portal's own origin. Existing log entries are
  migrated without clearing them.
- Admin sessions last eight hours and use Secure, HttpOnly, SameSite=Strict
  cookies. Changes require same-origin requests and CSRF tokens. Changing
  the admin password revokes all admin sessions.
- Online-only builds require successful HTTPS authorization. In the dual
  password build, a matching recovery hash authorizes the operation offline.
  Otherwise wrong passwords, connection failures, invalid certificates and
  unexpected responses block setup and uninstall.
- The initial EXE password can be changed after signing in. The portal does
  not display the current password.

Deploy the updated portal to enable the new log fields and cleanup control.
Rebuild and distribute the installer with the updated `os_win_installer/setup_auth.py`
to report actual computer names. Previously built or installed copies continue
to authenticate but report `Unknown` until their client code is updated. Local
recovery-password checks and offline attempts do not contact the portal and
therefore do not appear in its log.

## Server

Application: `/opt/remo-password-portal/`  
Private state: `/var/lib/remo-password-portal/`  
Service: `remo-password-portal.service`  
Port: TCP 443

The service starts at boot, runs as `ec2-user`, and has only the additional
capability needed to bind port 443. Other existing services keep their ports.
The SQLite database and TLS private key live outside the source repository.
Back up that directory securely; losing the database or certificate key can
interrupt verification. Check service status using:

```sh
sudo systemctl status remo-password-portal --no-pager
sudo journalctl -u remo-password-portal -n 40 --no-pager
```

The IP uses a private, self-signed certificate, so browsers show a certificate
warning. `server.crt` is the public certificate; the installer trusts it and
checks the server IP. This certificate expires in October 2036. Replacing its
key/certificate requires distributing a newly configured installer and
updating the saved trust configuration of existing installations. Never
disable certificate verification to bypass a mismatch.

## Development and deployment

Python 3.9 or later, standard library only:

```powershell
python -m unittest discover -s password_portal -p "test_*.py" -v
python -m unittest discover -s make/tests -p test_support_setup.py -v
python password_portal/deploy.py --identity "PATH_TO_PEM"
```

The first deployment initializes the server from the existing local installer
password hash and creates a random admin password. The deploy command returns
that admin password once; keep it private and change it after signing in.
Later deployments preserve the database, passwords and certificate.

`verify_live.py` prompts for the admin password without echoing it. It signs in,
adds two temporary passwords, checks acceptance and individual revocation, then
removes its temporary passwords. Existing password entries are preserved.
It does not start, install or remove an agent.

Use `make/package_windows_installer.py` with `os_win_installer/install.json`
to produce a new connected EXE. That config contains only the public endpoint
and trusted certificate, plus the recovery hash in dual-password builds.
Admin credentials and portal-managed P values are never bundled.

## Isolated 10443 installer with dynamic metadata

`install-dynamic-10443-v2.json` builds a separate EXE that uses only the new
`https://82.25.46.70:10443/` portal for P and installation settings. Its first
screen contains only the required P and C fields. Submitting verifies P and
retrieves the profile before installation; C is then used to link the agent.

The authenticated Installation settings form now also controls installation
path and Publisher. Leave path blank for Program Files / service name, or use
new subfolders such as `%ProgramFiles%\REMO\Agent`. The installer reads the
actual Program Files location from Windows. Existing vendor subfolders,
folders outside Program Files, and paths through junctions are refused so
the LocalSystem service inherits protected file permissions. Publisher changes the Installed Apps
entry; the UAC publisher still depends on the EXE's code signature.

Metadata is returned with names only when P and the separate built-in client
credential are accepted. New clients opt into `install_identity_version: 2`;
older clients continue receiving exactly their original four naming fields.
The embedded client credential can be extracted from a distributed EXE.
Custom portal values are never packaged into the installer. Installed agents
retain their saved profile even if the portal changes during a C retry.

The v6 installer (`install-dynamic-10443-v6.json`) derives each Task Manager
process description from that process's own portal executable filename. It
removes a terminal `.exe` (case insensitive), then inserts a space before each
capital after the first character unless a space is already present. Thus
`RemoDwAgentAcess.exe` becomes `Remo Dw Agent Acess`. Main and service processes
can have different friendly labels when their filenames differ. This is a literal
capital-letter rule: `ABC.exe` becomes `A B C`.
The **Service display name** is formatted separately with the same rule:
`RemoDwAgent` becomes `Remo Dw Agent` for Services and Control Panel. Executable
filenames, the internal Windows service name, publisher and installation path
retain their portal values. Formatting never changes the saved raw profile.
The earlier v5 installer uses the Service display name directly for both process
descriptions. Its behavior is retained when rebuilding its original configuration.
This uses the existing authenticated profile; no new portal field or server
deployment is needed. Saving a new name affects subsequent installations or
replacements, not processes that are already installed. Task Manager controls
grouping and its Details tab still shows the executable filenames.
The v6 formatting mode is saved with the installation so uninstall and replacement
rollback use the correct service display label for that installation.
Only installed copies receive the version-resource changes, before they are
started. Other version metadata, copyright, icons and manifests are preserved.
Changing an EXE's resources changes its signed bytes; these customized copies
do not retain the original runtime's valid Authenticode signature.

`update_isolated_metadata.py --password-stdin` updates only the existing
10443 service, backs up its code/database, checks health and compares old
listeners, process IDs, source files and credentials before/after. It does not
restart any other service. `verify_isolated_live.py --password-stdin
--install-config install-dynamic-10443-v2.json` checks both profile versions
with a temporary P and session, then removes those temporary credentials.

## Command Prompt / DW Terminal uninstall

Run this from an administrator Command Prompt or an elevated DW Terminal:

```cmd
"C:\Program Files\MyDWagent2\uninstall.cmd"
```

The command prompts for a password. Any active server password or the bundled
local recovery password works. No password is placed in command arguments.
An authenticated worker runs separately from the remote terminal and rechecks
the credential through a private stdin pipe before removing services and app
registration. A temporary cleanup helper waits for the worker to exit, then
removes the installation folder. It refuses unmarked paths and does not follow
directory junctions. Removing the agent disconnects its remote sessions.
Failures are recorded in `console-uninstall.log` in the installation folder.
This command is included only in new builds; older installations need the
updated installer. GUI and terminal uninstall share the same password rules.
