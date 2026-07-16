#!/usr/bin/env bash
# pcap_overview.sh - 一键输出抓包文件的整体概览
# 用法: pcap_overview.sh <capture.pcap> [out_dir]
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "用法: $0 <capture.pcap> [out_dir]" >&2
  exit 1
fi

PCAP="$1"
OUT="${2:-/tmp/pcap_overview}"
mkdir -p "$OUT"

if [ ! -f "$PCAP" ]; then
  echo "错误: 找不到文件 $PCAP" >&2
  exit 1
fi

echo "===== 协议分层 (protocol hierarchy) ====="
tshark -r "$PCAP" -q -z io,phs

echo
echo "===== TCP 会话 (conversations) ====="
tshark -r "$PCAP" -q -z conv,tcp

echo
echo "===== IP 端点 (endpoints) ====="
tshark -r "$PCAP" -q -z endpoints,ip

echo
echo "===== 每秒 IO 统计 (io,stat,1) ====="
tshark -r "$PCAP" -q -z io,stat,1

echo
echo "===== 唯一目标 IP ====="
tshark -r "$PCAP" -T fields -e ip.dst | sort -u > "$OUT/unique_dest_ips.txt"
wc -l < "$OUT/unique_dest_ips.txt" | xargs echo "目标 IP 数量:"
