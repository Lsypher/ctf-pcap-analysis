---
name: ctf-pcap-analysis
description: >-
  CTF and forensics PCAP analysis playbook using tshark/Wireshark CLI. Use when the user sends a pcap/pcapng file and an instruction in natural language such as "find suspicious DNS queries", "extract transferred files", "find the flag", "decode USB keystrokes", or "detect DNS tunneling / beaconing / data exfiltration". Covers Wireshark display filters, protocol analysis (HTTP/DNS/FTP/SMTP/USB/ICMP/WiFi/TLS), file carving, credential harvesting, covert channel detection, PCAP repair, and tshark command-line workflows.
---

# SKILL: Traffic Analysis & PCAP — Expert Analysis Playbook

> **WORKFLOW HINT**: 先概览（`scripts/pcap_overview.sh`）再按协议深入。模型常漏的点：USB 键盘 HID 解码模式、DNS 隧道检测启发式、TLS 解密（SSLKEYLOGFILE / RSA 私钥）流程。

## 0. HOW TO USE
 
This skill is for analyzing a pcap/pcapng file the user provides. Typical natural-language requests:
 
- "找出这个抓包里访问可疑域名的 DNS 查询" → §2 DNS + §3 DNS tunneling + beaconing filters
- "提取传输的文件 / 找 flag" → §4 file carving, `frame contains "flag{"`, §6 export-objects
- "解码 USB 键盘流量" → §3 USB HID
- "检测 DNS 隧道 / 信标 / 数据泄露" → §3 + §4 covert channel + beaconing filters
 
Workflow: (1) repair if needed (§1) → (2) overview with `tshark -q -z io,phs` (§6) → (3) apply protocol/display filters (§2-§3) → (4) extract artifacts (§4, §6) → (5) follow suspicious streams.

### Bundled scripts (`scripts/`)

- `pcap_overview.sh <pcap> [out_dir]` — 一键输出协议分层、TCP 会话、IP 端点、IO 统计、唯一目标 IP。
- `dns_recon.sh <pcap>` — 枚举 DNS 查询名、TXT/超长查询、可疑 TLD、端口扫描计数。
- `export_objects.sh <pcap> [out_dir]` — 导出 HTTP/SMB/TFTP/FTP/IMF 传输对象并哈希。
- `usb_hid_decode.py` — 解码 USB 键盘 HID 流量为文本（见 §3 USB）。


---

## 1. PCAP REPAIR

```bash
pcapfix corrupted.pcap -o fixed.pcap           # repair corrupted PCAP
# Magic bytes: d4c3b2a1=pcap(LE), a1b2c3d4=pcap(BE), 0a0d0d0a=pcapng
editcap -F pcap capture.pcapng capture.pcap    # convert pcapng→pcap
mergecap -w merged.pcap file1.pcap file2.pcap  # merge captures
```

---

## 2. WIRESHARK ESSENTIAL FILTERS

### IP / Host Filters

```
ip.addr == 10.0.0.1                  # source or destination
ip.src == 10.0.0.1                   # source only
ip.dst == 10.0.0.1                   # destination only
ip.addr == 10.0.0.0/24              # subnet
!(ip.addr == 10.0.0.1)              # exclude host
```

### Protocol Filters

```
http                                  # all HTTP
dns                                   # all DNS
tcp                                   # all TCP
ftp                                   # all FTP
smtp                                  # all SMTP
tls                                   # all TLS/SSL
icmp                                  # all ICMP
arp                                   # all ARP
```

### TCP / Stream

```
tcp.stream eq 5                       # follow specific TCP stream
tcp.port == 80                        # traffic on port 80
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN packets (connection starts)
tcp.analysis.retransmission           # retransmitted packets
tcp.len > 0                           # packets with payload
```

### HTTP

```
http.request.method == "POST"         # POST requests
http.request.method == "GET"          # GET requests
http.response.code == 200             # successful responses
http.response.code >= 400             # error responses
http.request.uri contains "login"     # URI contains string
http.host contains "target.com"       # specific host
http.content_type contains "json"     # JSON responses
http.cookie contains "session"        # session cookies
http.request.full_uri                 # show full URIs (column)
```

### DNS
 
```
dns.qry.name contains "evil.com"     # specific domain queries
dns.qry.type == 1                    # A records
dns.qry.type == 28                   # AAAA records
dns.qry.type == 16                   # TXT records
dns.flags.response == 1              # DNS responses only
dns.resp.len > 100                   # large DNS responses
dns.flags.rcode != 0                 # DNS errors / NXDOMAIN
```

### Suspicious Domain / Beaconing (CTF + IR)
 
```
# Queries to free/suspicious TLDs often seen in malware or CTF exfil:
dns.qry.name contains ".xyz" || dns.qry.name contains ".top" || dns.qry.name contains ".tk" || dns.qry.name contains ".ml" || dns.qry.name contains ".ga"
 
# List every unique queried name (start here for "find suspicious DNS" tasks):
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e ip.src -e dns.qry.name | sort -u
 
# Detect beaconing: regular-interval connections to one host
tshark -r capture.pcap -Y "ip.dst == 203.0.113.50" -T fields -e frame.time_relative -e ip.src -e tcp.dstport
 
# Port scan / recon: one source hitting many destination ports
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head -20
```


### TLS

```
tls.handshake.type == 1              # Client Hello
tls.handshake.type == 2              # Server Hello
tls.handshake.extensions.server_name  # SNI (hostname)
tls.handshake.type == 11             # Certificate
```

### Content Search

```
frame contains "password"             # search in raw bytes
frame contains "flag{"                # CTF flag pattern
tcp contains "admin"                  # search in TCP payload
```

### Artifact Presentation Rules

**核心原则：AI 禁止自行选定唯一答案。所有可疑结果必须全部列出，由用户判断。**

AI 分析 PCAP 后，必须主动展示以下内容给用户：

- 所有提取的文件（路径 + SHA256）
- **所有**可疑字符串（从 follow stream、DNS query、HTTP body 等中提取），不得遗漏
- 所有需要用户进一步解码/处理的半成品（附带编码类型判断）

---
#### 强制性要求（违反即视为无效分析）

1. **逐消息类型提取**：必须按协议中每个不同的消息类型/阶段分别提取可读字符串，不得跳过任何类型。例如自定义 UDP 协议中 type 0x00、type 0x01、type 0x02 等各自 payload 中的 ASCII 字符串都要单独列出。

2. **精确标注来源**：每条候选必须包含：
   - 帧号（frame number）
   - 消息类型 / 协议阶段
   - 在 payload 中的偏移位置（hex offset）
   - 字符串长度
   - 所属通信方向（谁→谁）

3. **排除说明**：如果某个可读字符串被判断为"无关"而未列入候选，必须在输出中说明排除理由（如"该值在所有会话中相同，属于协议固定标识"等）。

4. **结尾声明**：最终回复必须以 `以上共 N 个候选，请用户判断最终答案。` 结尾，不得附加任何暗示性结论。

#### 展示格式

每条候选必须严格按以下格式输出：

```
[置信度] <值>
  → 帧号: <number>
  → 方向: <src> → <dst>
  → 消息类型: <type>
  → payload 偏移: <offset>
  → 长度: <length> 字节
  → 原始 hex: <hex dump>
  → 可能含义: <分析>
  → 建议: <下一步操作>
```

**置信度分级规则：**
- `HIGH`：语义明确（如 flag 格式匹配、已知协议字段、可解码为有意义内容）
- `MEDIUM`：格式可疑（如特定长度、base64 特征、协议关键字段位置）
- `LOW`：仅因是可读 ASCII 而列入，无其他上下文支持

#### 示例（以自定义 UDP 协议为例）

```
[MEDIUM] uU1vUKcSzuCcF6mylNpNTPoPngRP5G7t
  → 帧号: 18215
  → 方向: 172.18.0.125 → 172.18.0.1
  → 消息类型: 0x00（初始握手）
  → payload 偏移: 0x14（魔数 P05= 之后）
  → 长度: 32 字节
  → 原始 hex: 75553176554b63537a75436346366d796c4e704e54506f506e67525035473774
  → 可能含义: 会话密钥 / 客户端标识
  → 建议: 尝试作为 flag 直接提交，或检查是否可解码

[MEDIUM] DtX0GScM9dwrgZht
  → 帧号: 18217
  → 方向: 172.18.0.125 → 172.18.0.1
  → 消息类型: 0x01（认证）
  → payload 偏移: 0x15（0xff 前缀字节之后）
  → 长度: 16 字节
  → 原始 hex: 447458304753634d39647772675a6874
  → 可能含义: 会话密钥 / 认证令牌
  → 建议: 尝试作为 flag 直接提交，或检查是否可解码

→ 两个可疑候选均来自攻击者流量，请用户判断哪个是答案
```

**注意**：上例中 type 字段（0x00/0x01）、偏移值、帧号均为占位，实际分析时需从抓包中精确提取。

---
#### 隐式 flag 处理（无 flag{} 包裹时）

当 flag 没有明确格式时，必须：

1. 分析协议每个消息类型的 payload，逐字节提取 ASCII 可读范围（0x20-0x7e）的连续字符串
2. 提取所有协议数据阶段的明文可读字符串，无论其看起来是否"像 flag"
3. 禁止因"看起来像随机数据"或"长度不对"而跳过某个候选
4. 每条候选标注其协议阶段、消息类型、方向、帧号

#### 输出前自检清单

AI 在给出最终答案前，必须逐一核对以下清单，核对过程不在回复中展示：

```
☐ 是否从每个不同的消息类型/协议阶段中都提取了可读字符串？
☐ 是否遍历了攻击者相关的所有帧，而非仅查看前几帧？
☐ 是否提取了每个消息类型中所有可变长度的字段值？
☐ 所有候选是否都标注了帧号和来源偏移？
☐ 是否有可读字符串被遗漏？如有，是否已说明排除理由？
☐ 是否明确请求用户做出最终判断？
☐ 是否未在回复中暗示或引导用户选择特定答案？
```

**自检全部通过后方可输出最终回复。**

#### flag 搜索策略
- 向用户确认 flag 格式（如 `flag{}`、`CTF{}`、`key{}` 或其他）
- 用用户提供的格式搜索，同时用 `frame contains "flag"` 做宽泛兜底
- 对可疑字段尝试 base64/hex/rot13 解码后再搜索
- 对无明确格式的隐式 flag，将所有可疑字符串全部列出，标注来源和可能用途
- **AI 不做最终判定，永远把选择权交给用户**

---

## 3. PROTOCOL ANALYSIS

### HTTP — Follow Stream & Extract
 
```bash
# CLI equivalents (no GUI needed):
tshark -r capture.pcap -q -z follow,tcp,ascii,0        # follow stream 0 as text
tshark -r capture.pcap --export-objects http,/tmp/exported/   # carve HTTP files
 
# Useful filters for credential hunting:
tshark -r capture.pcap -Y "http.request.method==\"POST\" && frame contains \"password\"" -T fields -e http.file_data
tshark -r capture.pcap -Y "http.request.method==\"POST\" && frame contains \"login\"" -T fields -e http.file_data
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authorization   # Basic auth (base64)
```


### HTTPS / TLS Decryption

```bash
# Method 1: SSLKEYLOGFILE (pre-master secrets from browser)
# Set environment variable BEFORE opening browser:
export SSLKEYLOGFILE=/tmp/sslkeys.log
firefox https://target.com

# Wireshark: Edit → Preferences → Protocols → TLS
# → (Pre)-Master-Secret log filename: /tmp/sslkeys.log

# Method 2: Server private key (for RSA key exchange only)
# Wireshark: Edit → Preferences → Protocols → TLS → RSA keys list
# → Add: IP, Port, Protocol, Key file (.pem)
```

### DNS — Tunneling Detection

```bash
# Indicators of DNS tunneling:
# 1. Unusually long subdomain names (>30 chars)
# 2. High volume of TXT record queries/responses
# 3. Consistent query patterns to same domain
# 4. Base32/Base64-like subdomain strings
# 5. High query frequency from single host

# Wireshark filter for suspicious DNS:
dns.qry.name.len > 50                # long query names
dns.qry.type == 16                   # TXT records (common for tunneling)
dns.resp.len > 512                   # large DNS responses

# tshark extraction:
tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e dns.qry.name
```

### FTP — Credential & File Extraction
 
```bash
# FTP credentials (plaintext):
tshark -r capture.pcap -Y "ftp.request.command==USER || ftp.request.command==PASS" -T fields -e ftp.request.arg
 
# FTP file transfer reconstruction:
# 最简单: tshark 内置 ftp-data 对象导出
tshark -r capture.pcap --export-objects ftp-data,/tmp/ftp_obj/
# 手动方式: FTP 用独立数据通道 (通常端口 20 或动态), 跟流存 raw 后再 carve
tshark -r capture.pcap -q -z follow,tcp,raw,<stream> > ftp_data.bin
binwalk -e ftp_data.bin
```


### SMTP — Email Content Extraction
 
```bash
# Follow the TCP stream of the SMTP session to see MAIL FROM/RCPT TO/DATA
tshark -r capture.pcap -q -z follow,tcp,ascii,0
 
# Attachments: base64 in MIME → decode Content-Transfer-Encoding blocks
tshark -r capture.pcap -Y "smtp.req.command==\"AUTH\"" -T fields -e smtp.req.parameter   # auth (often base64)
# smtp.req.body 字段不存在; 邮件正文/附件需跟流后手动 base64 解码:
tshark -r capture.pcap -q -z follow,tcp,ascii,<stream> > mail.txt   # 定位 attachment 的 base64 块并解码
# 或导出 IMF (Internet Message Format) 对象:
tshark -r capture.pcap --export-objects imf,/tmp/mail_obj/
```


### USB — Keyboard HID Capture Decode

```bash
# USB HID keyboard traffic: interrupt transfers with 8-byte data
# Filter: usb.transfer_type == 0x01

# Extract keystrokes (byte[0]=modifier, byte[2]=keycode):
tshark -r usb.pcap -Y "usb.capdata && usb.data_len == 8" -T fields -e usb.capdata > keystrokes.txt

# Decode keycodes → text (skill script):
python3 scripts/usb_hid_decode.py keystrokes.txt
# 或直接读 pcap: python3 scripts/usb_hid_decode.py --pcap usb.pcap
# 0x04=a..0x1d=z, 0x1e=1..0x27=0, 0x28=Enter, 0x2c=Space
```

### WiFi — WPA Handshake

```bash
# Capture: airodump-ng --bssid AP_MAC -w capture wlan0mon
# Convert + crack: hcxpcapngtool -o hash.hc22000 capture.pcap
hashcat -m 22000 hash.hc22000 wordlist.txt
# Deauth detection: wlan.fc.type_subtype == 0x0c
```

### ICMP — Data Exfiltration

```bash
# ICMP payload analysis
# Normal ping: 32 or 64 bytes of pattern data
# Exfiltration: meaningful data in ICMP payload

# Filter:
icmp && data.len > 48                 # unusual ICMP payload size
icmp.type == 8                        # echo requests

# Extract ICMP payloads:
tshark -r capture.pcap -Y "icmp.type==8" -T fields -e data.data
```

---

## 4. DATA EXTRACTION

### File Carving
 
```bash
# tshark exports objects directly (no GUI):
# 支持的类型: http smb tftp ftp-data imf dicom x509af
tshark -r capture.pcap --export-objects http,/tmp/http_obj/
tshark -r capture.pcap --export-objects smb,/tmp/smb_obj/
tshark -r capture.pcap --export-objects tftp,/tmp/tftp_obj/
tshark -r capture.pcap --export-objects ftp-data,/tmp/ftp_obj/
 
# Manual from reassembled stream: follow TCP stream, save raw, then carve
tshark -r capture.pcap -q -z follow,tcp,raw,0 > stream0.bin
binwalk -e stream0.bin
foremost -i stream0.bin -o carved/
```


### Credential Harvesting

```bash
# Plaintext: ftp || telnet || http.authbasic || smtp || pop || imap
# NTLM: ntlmssp.auth.username → extract challenge/response from NTLMSSP messages
# Hash format: user::domain:challenge:NTProofStr:blob → hashcat -m 5600
```

### Covert Channel Detection

Indicators: DNS with long subdomains, ICMP with large payloads, HTTP with encoded headers, regular beacon intervals (C2). Use `tshark -q -z io,stat,1` and `-z conv,tcp` for statistical anomaly detection.

---

## 5. NETWORKMINER

```bash
# Automated PCAP analysis: sudo apt install networkminer
# Open PCAP → auto-extracts: Files, Images, Credentials, Sessions, DNS
# Files tab: carved from HTTP/SMB/FTP | Credentials tab: plaintext creds
```

---

## 6. TSHARK COMMAND-LINE ANALYSIS

```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data
tshark -r capture.pcap -q -z io,stat,1                # I/O graph
tshark -r capture.pcap -q -z conv,tcp                  # TCP conversations
tshark -r capture.pcap -q -z endpoints,ip              # IP endpoints
tshark -r capture.pcap -q -z io,phs                    # protocol hierarchy
tshark -r capture.pcap -q -z follow,tcp,ascii,0        # follow stream 0
tshark -r capture.pcap --export-objects http,/tmp/exported/
 
# Artifact / IOC extraction (CTF + IR)
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u > urls.txt
tshark -r capture.pcap -T fields -e ip.dst | sort -u > unique_dest_ips.txt
tshark -r capture.pcap -Y "tls.handshake.type==11" -T fields -e x509sat.uTF8String -e x509ce.dNSName   # cert info
tshark -r capture.pcap -Y "smb2" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.filename -e smb2.cmd
tshark -r capture.pcap -Y "ip.addr==10.10.5.23 && tcp.port==4444" -w evidence.pcapng   # export subset
find /tmp/exported/ -type f -exec sha256sum {} \; > extracted_file_hashes.txt
```

---

## 7. DECISION TREE

```
PCAP file for analysis
│
├── File won't open?
│   ├── Check magic bytes: xxd | head (§1)
│   ├── Repair: pcapfix (§1)
│   └── Convert: editcap pcapng→pcap (§1)
│
├── What's in the capture? (Quick overview)
│   ├── tshark -q -z io,phs (protocol hierarchy) (§6)
│   ├── tshark -q -z conv,tcp (conversations) (§6)
│   └── tshark -q -z endpoints,ip (endpoints) (§6)
│
├── HTTP traffic?
│   ├── Export objects: tshark --export-objects http,/tmp/exported/ (§4)
│   ├── Credential hunt: POST + password/login filters (§3)
│   ├── Follow streams: tshark -q -z follow,tcp,ascii,N (§3/§6)
│   └── Encrypted (HTTPS)? → need SSLKEYLOGFILE or RSA key (§3)
│
├── DNS traffic?
│   ├── Long subdomains? → DNS tunneling (§3)
│   ├── High TXT record volume? → DNS exfiltration (§3)
│   ├── Extract all queries: tshark -Y dns -T fields -e dns.qry.name (§6)
│   └── DNS rebinding? → check for alternating A record responses
│
├── FTP / Telnet / SMTP?
│   ├── Extract credentials (plaintext) (§3)
│   ├── Reconstruct file transfers (follow data stream) (§3)
│   └── Email content and attachments (base64 decode) (§3)
│
├── USB traffic?
│   ├── Keyboard HID → decode keystrokes (§3)
│   ├── Storage → extract transferred files
│   └── Check transfer_type and data_len fields
│
├── WiFi traffic?
│   ├── WPA handshake → crack with hashcat (§3)
│   ├── Deauth frames → detect attack (§3)
│   └── Probe requests → device fingerprinting
│
├── ICMP traffic?
│   ├── Large/variable payloads → data exfiltration (§3)
│   ├── Regular pattern → ICMP tunnel (§3)
│   └── Extract payloads: tshark -Y icmp -T fields -e data.data
│
├── Suspicious patterns?
│   ├── Regular beacon interval → C2 communication (§4)
│   ├── Unusual port/protocol combos → covert channel (§4)
│   ├── High volume to single external IP → data exfil (§4)
│   └── Encrypted traffic without SNI → suspicious tunnel
│
├── Need automated extraction?
│   ├── NetworkMiner (GUI, optional): sudo apt install networkminer → auto-extracts Files/Credentials/Sessions/DNS
│   ├── tshark --export-objects for HTTP/SMB/TFTP files (§4/§6)
│   └── binwalk/foremost on exported streams (§4)
│
└── Found suspicious data?
    ├── User provided flag format? → Search with that format + wide "flag" search
    ├── Looks encoded (base64/hex)? → Decode from stream, show result
    ├── Partial match in DNS/HTTP payload? → Extract full context, show candidate
    ├── Custom/unknown protocol? → 按消息类型逐类型提取所有可读 ASCII 字符串作为候选
    ├── 执行输出前自检清单（Artifact Presentation Rules 中有详细清单）
    └── 按 Artifact Presentation Rules 的展示格式列出 ALL candidates，请求用户判断
```
