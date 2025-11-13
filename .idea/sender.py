# sender.py
import socket
import json
import time
import argparse
from ca_keystream import ca_keystream
import os

def str_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def bits_from_seed_string(seed_str: str, width: int):
    # Produce a deterministic bit list from seed string (hash-like)
    bs = []
    # Use bytes of seed_str
    data = seed_str.encode('utf-8')
    # repeat/extend to reach width
    i = 0
    while len(bs) < width:
        byte = data[i % len(data)]
        for bitpos in range(7, -1, -1):
            bs.append((byte >> bitpos) & 1)
        i += 1
    return bs[:width]

def send_command(command: str, seed_str: str, rule: int, dst_ip='127.0.0.1', dst_port=9999, seq=0):
    payload = str_to_bytes(command)
    ks = ca_keystream(bits_from_seed_string(seed_str, 32), rule, len(payload))
    obf = xor_bytes(payload, ks)
    packet = {
        "id": os.getpid(),
        "seq": seq,
        "seed": seed_str,
        "rule": rule,
        "payload_hex": obf.hex()
    }
    data = json.dumps(packet).encode('utf-8')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, (dst_ip, dst_port))
    s.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", default="127.0.0.1", help="destination IP")
    ap.add_argument("--port", type=int, default=9999, help="destination port")
    ap.add_argument("--seed", default="college-demo", help="CA seed string")
    ap.add_argument("--rule", type=int, default=30, help="CA rule (0-255), default 30")
    args = ap.parse_args()

    # Example demo commands
    commands = [
        "PING",
        "LIST DIR",
        "RUN:calc.exe",
        "ECHO:Hello-from-StarC2"
    ]
    seq = 0
    for cmd in commands:
        send_command(cmd, args.seed, args.rule, dst_ip=args.dst, dst_port=args.port, seq=seq)
        print(f"Sent seq={seq} cmd={cmd}")
        seq += 1
        time.sleep(0.7)
