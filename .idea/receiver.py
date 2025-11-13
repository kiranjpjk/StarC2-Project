# receiver.py
import socket
import json
from ca_keystream import ca_keystream
from typing import Tuple
import csv
import time
from datetime import datetime

HOST = '127.0.0.1'
PORT = 9999

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def bits_from_seed_string(seed_str: str, width: int):
    bs = []
    data = seed_str.encode('utf-8')
    i = 0
    while len(bs) < width:
        byte = data[i % len(data)]
        for bitpos in range(7, -1, -1):
            bs.append((byte >> bitpos) & 1)
        i += 1
    return bs[:width]

def decode_packet(pkt_bytes: bytes) -> Tuple[bool, dict]:
    try:
        data = json.loads(pkt_bytes.decode('utf-8'))
        obf = hex_to_bytes(data['payload_hex'])
        rule = int(data['rule'])
        seed = str(data['seed'])
        ks = ca_keystream(bits_from_seed_string(seed, 32), rule, len(obf))
        plain = xor_bytes(obf, ks)
        try:
            text = plain.decode('utf-8')
        except:
            text = "<binary>"
        data['decoded'] = text
        data['timestamp'] = datetime.utcnow().isoformat()
        data['decode_ok'] = True
        return True, data
    except Exception as e:
        return False, {"error": str(e)}

def write_report(rows, fname='detection_report.csv'):
    keys = ['timestamp','id','seq','seed','rule','payload_hex','decoded']
    with open(fname, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, '') for k in keys})

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[Receiver] Listening on {HOST}:{PORT} ... (press Ctrl-C to stop)")
    rows = []
    try:
        while True:
            pkt, addr = sock.recvfrom(65535)
            ok, data = decode_packet(pkt)
            if ok:
                print(f"[{data['timestamp']}] from {addr} seq={data['seq']} decoded='{data['decoded']}'")
                rows.append(data)
            else:
                print("Failed to decode packet:", data)
    except KeyboardInterrupt:
        print("Stopping receiver. Writing detection report...")
        write_report(rows)
        print("Report saved to detection_report.csv")
