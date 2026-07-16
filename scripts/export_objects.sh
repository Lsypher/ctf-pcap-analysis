#!/usr/bin/env bash
# export_objects.sh - 导出抓包中传输的文件对象 (HTTP/SMB/TFTP)
# 用法: export_objects.sh <capture.pcap> [out_dir]
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "用法: $0 <capture.pcap> [out_dir]" >&2
  exit 1
fi

PCAP="$1"
OUT="${2:-/tmp/pcap_objects}"
mkdir -p "$OUT/http" "$OUT/smb" "$OUT/tftp" "$OUT/ftp" "$OUT/imf"

echo "导出 HTTP 对象 -> $OUT/http"
tshark -r "$PCAP" --export-objects http,"$OUT/http" 2>/dev/null || echo "  (无 HTTP 对象或协议不支持)"

echo "导出 SMB 对象 -> $OUT/smb"
tshark -r "$PCAP" --export-objects smb,"$OUT/smb" 2>/dev/null || echo "  (无 SMB 对象或协议不支持)"

echo "导出 TFTP 对象 -> $OUT/tftp"
tshark -r "$PCAP" --export-objects tftp,"$OUT/tftp" 2>/dev/null || echo "  (无 TFTP 对象或协议不支持)"

echo "导出 FTP 数据对象 -> $OUT/ftp"
tshark -r "$PCAP" --export-objects ftp-data,"$OUT/ftp" 2>/dev/null || echo "  (无 FTP 对象或协议不支持)"

echo "导出 IMF 邮件对象 -> $OUT/imf"
tshark -r "$PCAP" --export-objects imf,"$OUT/imf" 2>/dev/null || echo "  (无 IMF 对象或协议不支持)"

echo
echo "提取文件哈希:"
find "$OUT" -type f -exec sha256sum {} \; > "$OUT/extracted_file_hashes.txt"
cat "$OUT/extracted_file_hashes.txt"
