#!/usr/bin/env bash
# dns_recon.sh - 枚举 DNS 查询并检测隧道/信标特征
# 用法: dns_recon.sh <capture.pcap>
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "用法: $0 <capture.pcap>" >&2
  exit 1
fi

PCAP="$1"

echo "===== 所有唯一 DNS 查询名 (含来源 IP) ====="
tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e ip.src -e dns.qry.name \
  | sort -u

echo
echo "===== DNS 响应中 TXT 记录 (隧道常用) ====="
tshark -r "$PCAP" -Y "dns.qry.type==16" -T fields -e dns.qry.name

echo
echo "===== 超长查询名 (>50 字符, 隧道嫌疑) ====="
tshark -r "$PCAP" -Y "dns.qry.name.len > 50" -T fields -e ip.src -e dns.qry.name

echo
echo "===== 可疑免费 TLD (.xyz/.top/.tk/.ml/.ga) ====="
tshark -r "$PCAP" -Y 'dns.qry.name contains ".xyz" || dns.qry.name contains ".top" || dns.qry.name contains ".tk" || dns.qry.name contains ".ml" || dns.qry.name contains ".ga"' \
  -T fields -e ip.src -e dns.qry.name | sort -u

echo
echo "===== 端口扫描/侦察: SYN 包目标端口计数 ====="
tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head -20
