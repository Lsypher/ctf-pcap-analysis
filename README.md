# ctf-pcap-analysis

CTF / 取证 PCAP 流量分析 skill，用于 [opencode](https://opencode.ai) CLI。

## 功能

- Wireshark / tshark 显示过滤器速查
- 协议分析：HTTP、DNS、FTP、SMTP、USB、ICMP、WiFi、TLS
- 文件导出（carving）：HTTP/SMB/TFTP/FTP/IMF 对象提取
- USB 键盘 HID 解码
- DNS 隧道 / 信标检测
- 凭据提取（明文 / NTLM）
- 内置辅助脚本

## 安装

```bash
# 克隆到 opencode skills 目录
git clone https://github.com/Lsypher/ctf-pcap-analysis.git ~/.opencode/skills/ctf-pcap-analysis
```

## 使用

安装后在 opencode 中直接使用，例如：

- "找出这个抓包里访问可疑域名的 DNS 查询"
- "提取传输的文件"
- "解码 USB 键盘流量"
- "检测 DNS 隧道"

### 内置脚本

| 脚本 | 说明 |
|------|------|
| `scripts/pcap_overview.sh <pcap>` | 一键输出协议分层、TCP 会话、IP 端点、IO 统计 |
| `scripts/dns_recon.sh <pcap>` | DNS 查询枚举、TXT 记录、可疑 TLD、端口扫描 |
| `scripts/export_objects.sh <pcap>` | 导出 HTTP/SMB/TFTP/FTP/IMF 对象并哈希 |
| `scripts/usb_hid_decode.py <keystrokes.txt>` | USB 键盘 HID 解码为文本 |

## 依赖

- [tshark](https://www.wireshark.org/) (必须)
- [pcapfix](https://0xdeadbeef.github.io/pcapfix/) (可选，用于修复损坏的 PCAP)
- [binwalk](https://github.com/ReFirmLabs/binwalk) / [foremost](https://www.kali.org/tools/foremost/) (可选，用于文件雕刻)

## License

MIT
