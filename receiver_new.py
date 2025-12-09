#!/usr/bin/env python3
"""
STAR-C2: RECEIVER
Listens for Type 8 and Type 3 ICMP packets
- Type 8 (Echo Request): REPLIES with Type 0 (Echo Reply) + ACK
- Type 3 (Destination Unreachable): SILENT (no reply)
"""

import struct
import sys
import random
import time
import logging
import socket
from typing import Optional, Dict, Any
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
# FRAME BUILDING & PARSING
# ============================================================================

def build_frame(msg: str) -> bytes:
    """Build STAR-C2 frame"""
    enc_msg = ca_encode_message(msg, SEED)
    frame = (
        SYNC +
        SATID +
        generate_metadata() +
        bytes([FRAME_ID]) +
        b'\x00' +
        SEED +
        enc_msg
    )
    
    if len(frame) < MIN_ICMP_PAYLOAD:
        pad_size = random.randint(MIN_ICMP_PAYLOAD - len(frame),
                                 MAX_ICMP_PAYLOAD - len(frame))
        frame += b'\x00' * pad_size
    return frame

def parse_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse STAR-C2 frame"""
    if len(data) < 25:
        return None
    
    try:
        if not data.startswith(SYNC):
            return None
        
        satid = data[4:7]
        metadata_bytes = data[7:19]
        frame_id = data[19]
        seed = data[21:25]
        enc_msg = data[25:]
        
        if frame_id != FRAME_ID:
            return None
        
        orbit, lat, lon, temp, volt = struct.unpack(">HffbB", metadata_bytes)
        msg = ca_decode_message(enc_msg, seed)
        
        return {
            'satid': satid.decode(errors='ignore'),
            'orbit': orbit,
            'lat': lat,
            'lon': lon,
            'temp': temp,
            'volt': volt,
            'msg': msg,
        }
    except Exception as e:
        logger.debug(f"Parse error: {e}")
        return None

def build_icmp_packet(src_ip: str, dst_ip: str, frame: bytes,
                     icmp_type: int, seq: int) -> IP:
    """Build ICMP packet"""
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type, seq=seq) / Raw(load=frame)
    return pkt

# ============================================================================
# RECEIVER CLASS
# ============================================================================

class Receiver:
    def __init__(self, my_ip: str, timeout: int = 60):
        self.my_ip = my_ip
        self.timeout = timeout
        self.message_count = 0
        self.messages = []
    
    def send_reply(self, sender_ip: str, seq: int, reply_msg: str) -> bool:
        """Send Type 0 (Echo Reply) back to sender"""
        try:
            frame = build_frame(reply_msg)
            pkt = build_icmp_packet(self.my_ip, sender_ip, frame,
                                   icmp_type=0, seq=seq)  # Type 0
            send(pkt, verbose=False)
            logger.info(f"[✓ REPLY SENT] Type 0 to {sender_ip}: {reply_msg}")
            return True
        except Exception as e:
            logger.error(f"Reply failed: {e}")
            return False
    
    def handler(self, pkt: Any) -> None:
        """Handle received ICMP packets"""
        try:
            if not pkt.haslayer(ICMP):
                return
            
            icmp_type = pkt[ICMP].type
            
            # Only handle Type 8 (Echo Request) and Type 3 (Destination Unreachable)
            if icmp_type not in [3, 8]:
                return
            
            if not pkt.haslayer(Raw):
                return
            
            data = pkt[Raw].load
            sender_ip = pkt[IP].src
            seq = pkt[ICMP].seq
            
            # Parse frame
            frame = parse_frame(data)
            if frame is None:
                return
            
            self.message_count += 1
            
            # ================================================================
            # DISPLAY MESSAGE
            # ================================================================
            
            type_name = "Type 8 (Echo Request)" if icmp_type == 8 else "Type 3 (Destination Unreachable)"
            
            print(f"\n{'═' * 70}")
            print(f"[✓ REQUEST #{self.message_count} - ICMP {type_name}]")
            print(f"{'═' * 70}")
            print(f"From: {sender_ip}")
            print(f"Sequence: {seq}")
            print(f"Message: {frame['msg']}")
            print(f"Orbit: {frame['orbit']} km")
            print(f"Position: {frame['lat']:.2f}°, {frame['lon']:.2f}°")
            print(f"Temp: {frame['temp']}°C")
            print(f"{'═' * 70}")
            
            # ================================================================
            # REPLY LOGIC
            # ================================================================
            
            if icmp_type == 8:
                # Type 8 → REPLY with Type 0
                print(f"[+] Sending Type 0 (Echo Reply)...")
                reply_msg = f"ACK-#{self.message_count}"
                self.send_reply(sender_ip, seq, reply_msg)
                print(f"[✓] Type 0 Reply sent: {reply_msg}\n")
            else:
                # Type 3 → NO REPLY (silent)
                print(f"[!] Type 3 detected - NO REPLY (silent)\n")
            
            # Store message
            self.messages.append({
                'count': self.message_count,
                'type': icmp_type,
                'from': sender_ip,
                'seq': seq,
                'msg': frame['msg']
            })
        
        except Exception as e:
            logger.debug(f"Handler error: {e}")
    
    def listen(self) -> None:
        """Listen for ICMP packets"""
        start_time = time.time()
        
        print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║ STAR-C2: RECEIVER ║
║ Type 8 (Echo Request) → REPLY with Type 0 ║
║ Type 3 (Destination Unreachable) → SILENT ║
╚═══════════════════════════════════════════════════════════════════╝

[+] Receiver IP: {self.my_ip}
[+] Timeout: {self.timeout} seconds

[+] Behavior:
    - Type 8 (Echo Request) → Auto-reply with Type 0 + ACK
    - Type 3 (Dest Unreachable) → No reply (stealth)

[!] Listening for ICMP packets...
[!] Press CTRL+C to stop
""")
        
        def stop_filter(pkt: Any) -> bool:
            elapsed = time.time() - start_time
            return elapsed >= self.timeout
        
        try:
            sniff(filter="icmp[0]=3 or icmp[0]=8",
                  prn=self.handler,
                  store=False,
                  stop_filter=stop_filter)
            
            elapsed = time.time() - start_time
            
            # Session summary
            print(f"\n{'═' * 70}")
            print(f"[SESSION SUMMARY]")
            print(f"{'═' * 70}")
            print(f"Duration: {elapsed:.1f}s")
            print(f"Total Messages: {self.message_count}")
            
            if self.messages:
                print(f"\nMessages received:")
                for msg in self.messages:
                    type_name = "Type 8" if msg['type'] == 8 else "Type 3"
                    print(f" #{msg['count']}: [{type_name}] {msg['msg']}")
            
            print(f"{'═' * 70}\n")
            print(f"[!] Timeout reached ({elapsed:.1f}s)")
        
        except KeyboardInterrupt:
            elapsed = time.time() - start_time
            print(f"\n\n[!] Stopped by user ({elapsed:.1f}s)")
            print(f"[!] Total messages: {self.message_count}")
        
        finally:
            sys.exit(0)

# ============================================================================
# MAIN
# ============================================================================

def main(timeout: Optional[int] = None):
    """Main receiver"""
    try:
        hostname = socket.gethostname()
        my_ip = socket.gethostbyname(hostname)
    except:
        my_ip = "127.0.0.1"
    
    if timeout is None:
        while True:
            try:
                timeout = int(input("[?] Enter timeout (seconds): "))
                if timeout > 0:
                    break
                print("[!] Must be positive")
            except ValueError:
                print("[!] Invalid number")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
                sys.exit(0)
    
    receiver = Receiver(my_ip, timeout=timeout)
    receiver.listen()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"""
STAR-C2: RECEIVER

Usage: python receiver.py [timeout_seconds]

Examples:
  python receiver.py          (prompt for timeout)
  python receiver.py 120      (120 second timeout)
  python receiver.py 600      (600 second timeout)

Behavior:
  - Listens for Type 8 (Echo Request) → REPLIES with Type 0
  - Listens for Type 3 (Destination Unreachable) → SILENT
""")
        sys.exit(1)
    
    timeout = None
    if len(sys.argv) >= 2:
        try:
            timeout = int(sys.argv[1])
            if timeout <= 0:
                print("[!] Error: Timeout must be positive")
                sys.exit(1)
        except ValueError:
            print(f"[!] Error: '{sys.argv[1]}' is not a number")
            sys.exit(1)
    
    main(timeout)
