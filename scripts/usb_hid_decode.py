#!/usr/bin/env python3
"""usb_hid_decode.py - 解码 USB 键盘 HID 流量为可读文本

用法:
    tshark -r usb.pcap -Y "usb.capdata && usb.data_len == 8" \
        -T fields -e usb.capdata > keystrokes.txt
    python3 usb_hid_decode.py keystrokes.txt

或直接从 pcap 读取:
    python3 usb_hid_decode.py --pcap usb.pcap

HID 键盘报告格式: byte[0]=修饰键, byte[2]=键值 (其余为 0)
"""
import sys
import re
import subprocess

# 普通键码 (Usage ID 0x04-0x1d -> a-z, 0x1e-0x27 -> 1-0, 0x28 Enter, 0x2c Space ...)
KEYCODE = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
    0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j', 0x0e: 'k', 0x0f: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
    0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x',
    0x1c: 'y', 0x1d: 'z',
    0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6',
    0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n', 0x2c: ' ', 0x2d: '-', 0x2e: '=', 0x2f: '[',
    0x30: ']', 0x31: '\\', 0x33: ';', 0x34: "'", 0x35: '`',
    0x36: ',', 0x37: '.', 0x38: '/',
    0x2b: '\t',
}

# 修饰键 (byte[0] 位): bit0=LeftCtrl bit1=LeftShift bit2=LeftAlt bit3=LeftGUI
SHIFT_KEYS = {0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D', 0x08: 'E', 0x09: 'F',
              0x0a: 'G', 0x0b: 'H', 0x0c: 'I', 0x0d: 'J', 0x0e: 'K', 0x0f: 'L',
              0x10: 'M', 0x11: 'N', 0x12: 'O', 0x13: 'P', 0x14: 'Q', 0x15: 'R',
              0x16: 'S', 0x17: 'T', 0x18: 'U', 0x19: 'V', 0x1a: 'W', 0x1b: 'X',
              0x1c: 'Y', 0x1d: 'Z',
              0x1e: '!', 0x1f: '@', 0x20: '#', 0x21: '$', 0x22: '%',
              0x23: '^', 0x24: '&', 0x25: '*', 0x26: '(', 0x27: ')'}


def decode_line(hexdata: str) -> str:
    h = hexdata.replace(':', '').strip()
    if len(h) < 16:
        return ''
    b = bytes.fromhex(h)
    modifier = b[0]
    keycode = b[2]
    if keycode == 0:
        return ''
    shifted = bool(modifier & 0x02)
    if shifted and keycode in SHIFT_KEYS:
        return SHIFT_KEYS[keycode]
    ch = KEYCODE.get(keycode, f'<0x{keycode:02x}>')
    return ch


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--pcap':
        pcap = sys.argv[2]
        out = subprocess.check_output(
            ['tshark', '-r', pcap, '-Y',
             'usb.capdata && usb.data_len == 8', '-T', 'fields', '-e', 'usb.capdata'],
            text=True)
        lines = out.splitlines()
    else:
        path = sys.argv[1] if len(sys.argv) > 1 else '-'
        if path == '-':
            lines = sys.stdin.read().splitlines()
        else:
            with open(path) as f:
                lines = f.read().splitlines()

    result = ''.join(decode_line(line) for line in lines)
    print(result)


if __name__ == '__main__':
    main()
