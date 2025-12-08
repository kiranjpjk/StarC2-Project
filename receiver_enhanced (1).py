# RECEIVER ENHANCED - AUTO-REPLY WITH ACKNOWLEDGMENT
# Based on star_c2_prod.py logic
# When receiver gets request → Automatically sends acknowledgment reply + displays message

import struct
import sys
import random
import time
import logging
import threading
import atexit
from typing import Tuple, Optional, Dict, Any
from scapy.all import IP, ICMP, Raw, send, sniff, conf
import numpy as np

# Disable Scapy's IPv6
conf.ipv6_enabled = False
conf.checkIPsrc = False
conf.verbose = 0

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# FRAME CONSTANTS
# ============================================================================

SYNC: bytes = b"STR1"
SATID: bytes = b"GXY"
FRAME_ID: int = 0xA1
SEED: bytes = b"\x12\x34\x56\x78"
MIN_ICMP_PAYLOAD: int = 64
MAX_ICMP_PAYLOAD: int = 256

# Message types
MSG_TYPE_REQUEST: int = 1
MSG_TYPE_REPLY: int = 0

# Global control
stop_sniffer: bool = False
start_time: float = 0.0
timeout_seconds: int = 60
received_messages: list = []

# ============================================================================
# CA KEYSTREAM (Same as star_c2_prod.py)
# ============================================================================

def rule90_step(arr: np.ndarray) -> np.ndarray:
    """Apply one Rule 90 CA iteration"""
    left = np.roll(arr, 1)
    right = np.roll(arr, -1)
    return (left ^ right).astype(np.uint8)

def ca_keystream(seed_bytes: bytes, length_bits: int) -> np.ndarray:
    """Generate pseudo-random keystream using Rule-90 CA"""
    state = np.unpackbits(np.frombuffer(seed_bytes, dtype=np.uint8))
    ks = np.zeros(length_bits, dtype=np.uint8)
    for i in range(length_bits):
        ks[i] = state[len(state) // 2]
        state = rule90_step(state)
    return ks

def ca_encode_message(msg: str, seed: bytes) -> bytes:
    """Encrypt message using Rule-90 CA keystream XOR"""
    if not msg:
        return b""
    msg_bits = np.unpackbits(np.frombuffer(msg.encode(), dtype=np.uint8))
    ks = ca_keystream(seed, len(msg_bits))
    enc_bits = msg_bits ^ ks
    enc_bytes = np.packbits(enc_bits).tobytes()
    return enc_bytes

def ca_decode_message(enc_bytes: bytes, seed: bytes) -> str:
    """Decrypt message (XOR is symmetric)"""
    if not enc_bytes:
        return ""
    enc_bits = np.unpackbits(np.frombuffer(enc_bytes, dtype=np.uint8))
    ks = ca_keystream(seed, len(enc_bits))
    dec_bits = enc_bits ^ ks
    if len(dec_bits) % 8 != 0:
        dec_bits = dec_bits[:len(dec_bits) - (len(dec_bits) % 8)]
    msg_bytes = np.packbits(dec_bits).tobytes()
    return msg_bytes.decode(errors='ignore')

# ============================================================================
# SATELLITE METADATA (Same as star_c2_prod.py)
# ============================================================================

class SatelliteMetadata:
    """Generate realistic satellite-like telemetry data"""

    @staticmethod
    def realistic_orbit() -> int:
        """Generate realistic orbital altitude"""
        return random.choice([
            random.randint(380, 420),      # LEO
            random.randint(19500, 20500),  # MEO
            random.randint(35700, 36300)   # GEO
        ])

    @staticmethod
    def realistic_location() -> Tuple[float, float]:
        """Generate realistic geographic location"""
        zones = [
            (10.0, 20.0, 70.0, 85.0),
            (-35.0, 35.0, -80.0, 80.0),
            (35.0, 75.0, -10.0, 40.0),
        ]
        lat_min, lat_max, lon_min, lon_max = random.choice(zones)
        lat = random.uniform(lat_min, lat_max)
        lon = random.uniform(lon_min, lon_max)
        return lat, lon

    @staticmethod
    def realistic_temperature() -> int:
        """Generate realistic temperature"""
        return random.randint(-100, 100)

    @staticmethod
    def realistic_voltage() -> int:
        """Generate realistic voltage"""
        return random.randint(28, 32)

    @staticmethod
    def generate() -> bytes:
        """Generate complete satellite metadata"""
        orbit = SatelliteMetadata.realistic_orbit()
        lat, lon = SatelliteMetadata.realistic_location()
        temp = SatelliteMetadata.realistic_temperature()
        volt = SatelliteMetadata.realistic_voltage()
        return struct.pack(">HffbB", orbit, lat, lon, temp, volt)

# ============================================================================
# FRAME PARSING (Enhanced with message type)
# ============================================================================

def parse_star_c2_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse STAR-C2 frame with message type support"""
    if len(data) < 25:
        return None

    try:
        if not data.startswith(SYNC):
            return None

        satid = data[4:7]
        metadata_bytes = data[7:19]
        frame_id = data[19]
        msg_type = data[20]  # NEW: Message type field
        seed = data[21:25]   # Seed offset changed
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
            'msg_type': msg_type
        }

    except Exception as e:
        logger.debug(f"Parse error: {e}")
        return None

# ============================================================================
# FRAME BUILDING (Enhanced for reply)
# ============================================================================

def build_star_c2_frame(msg: str, msg_type: int = MSG_TYPE_REPLY) -> bytes:
    """Build STAR-C2 frame with message type"""
    enc_msg = ca_encode_message(msg, SEED)
    
    frame = (
        SYNC +
        SATID +
        SatelliteMetadata.generate() +
        bytes([FRAME_ID]) +
        bytes([msg_type]) +  # NEW: Add message type
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
    """Build ICMP packet (type 0 = reply, type 8 = request)"""
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type, seq=seq) / Raw(load=frame)
    return pkt

# ============================================================================
# RECEIVER CLASS - AUTO-REPLY IMPLEMENTATION
# ============================================================================

class EnhancedReceiver:
    """Receiver that automatically replies to requests with acknowledgment"""

    def __init__(self, my_ip: str, timeout: int = 60):
        """Initialize receiver
        
        Args:
            my_ip: Receiver's IP address
            timeout: Listening timeout in seconds
        """
        self.my_ip = my_ip
        self.timeout = timeout
        self.seq_counter = random.randint(0, 1000)
        self.message_count = 0

    def send_reply(self, sender_ip: str, seq: int, reply_msg: str) -> bool:
        """Send ICMP REPLY (type 0) back to sender
        
        Args:
            sender_ip: IP of the sender
            seq: Sequence number to echo back (maintains 1:1 correspondence)
            reply_msg: Acknowledgment message to send
        
        Returns:
            True if reply sent successfully
        """
        try:
            frame = build_star_c2_frame(reply_msg, msg_type=MSG_TYPE_REPLY)
            pkt = build_icmp_packet(self.my_ip, sender_ip, frame, 
                                   icmp_type=0,  # REPLY
                                   seq=seq)
            send(pkt, verbose=False)
            logger.info(f"[✓ REPLY SENT] To: {sender_ip}, seq={seq}: '{reply_msg}'")
            return True

        except Exception as e:
            logger.error(f"Reply send failed: {e}")
            return False

    def handler(self, pkt: Any) -> None:
        """Handler for received ICMP REQUEST packets
        
        When REQUEST (type 8) is received:
        1. Parse the frame
        2. Decode the message
        3. Display message info
        4. Automatically send REPLY (type 0)
        """
        try:
            # Check if ICMP layer exists
            if not pkt.haslayer(ICMP):
                return

            # Check if it's a REQUEST (type 8)
            if pkt[ICMP].type != 8:
                return

            # Check if it has payload
            if not pkt.haslayer(Raw):
                return

            # Get the payload
            data = pkt[Raw].load
            sender_ip = pkt[IP].src
            receiver_ip = pkt[IP].dst
            seq = pkt[ICMP].seq

            # Parse the STAR-C2 frame
            frame = parse_star_c2_frame(data)
            if frame is None:
                return

            # Check if it's a REQUEST message type
            if frame['msg_type'] != MSG_TYPE_REQUEST:
                return

            self.message_count += 1

            # ================================================================
            # DISPLAY RECEIVED MESSAGE
            # ================================================================
            print(f"\n{'═' * 75}")
            print(f"[✓ REQUEST #{self.message_count} RECEIVED]")
            print(f"{'═' * 75}")
            print(f"From IP:           {sender_ip}")
            print(f"To IP:             {receiver_ip}")
            print(f"ICMP Seq:          {seq}")
            print(f"SATID:             {frame['satid']}")
            print(f"Orbit Altitude:    {frame['orbit']} km")
            print(f"Position:          {frame['lat']:.3f}°N, {frame['lon']:.3f}°E")
            print(f"Temperature:       {frame['temp']}°C")
            print(f"Voltage:           {frame['volt']}V")
            print(f"{'─' * 75}")
            print(f"[DECODED MESSAGE]: {frame['msg']}")
            print(f"{'═' * 75}\n")

            # ================================================================
            # AUTOMATICALLY SEND ACKNOWLEDGMENT REPLY
            # ================================================================
            # Reply message: Acknowledgment
            reply_msg = f"ACK-#{self.message_count}"
            
            # Send REPLY with same sequence number (1:1 correspondence)
            self.send_reply(sender_ip, seq, reply_msg)

            # Store message for record
            received_messages.append({
                'count': self.message_count,
                'from_ip': sender_ip,
                'to_ip': receiver_ip,
                'seq': seq,
                'message': frame['msg'],
                'timestamp': time.time()
            })

        except Exception as e:
            logger.debug(f"Handler error: {e}")

    def listen(self) -> None:
        """Start listening for ICMP REQUEST packets and auto-reply"""
        global stop_sniffer, start_time, timeout_seconds

        stop_sniffer = False
        start_time = time.time()
        timeout_seconds = self.timeout

        print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║ STAR-C2: RECEIVER WITH AUTO-REPLY (ENHANCED)                    ║
║ Maintains 1:1 REQUEST-REPLY correspondence                       ║
║ Defeats Sirine Sayadi's behavioral analysis detection            ║
╚═══════════════════════════════════════════════════════════════════╝

[+] RECEIVER INITIALIZED
[+] My IP:               {self.my_ip}
[+] Listening timeout:   {self.timeout} seconds
[+] Expected behavior:
    1. Wait for ICMP REQUEST (type 8) from sender
    2. Decode covert message using Rule-90 CA
    3. Display the decoded message
    4. AUTOMATICALLY send ICMP REPLY (type 0)
    5. Maintain 1:1 sequence correspondence
    6. Process continues until timeout

[!] Listening for covert ICMP requests...
[!] Press CTRL+C to stop manually
[!] Will auto-stop after {self.timeout} seconds

""")

        def stop_filter(pkt: Any) -> bool:
            """Check if we should stop sniffing (timeout or manual stop)"""
            elapsed = time.time() - start_time
            return elapsed >= timeout_seconds or stop_sniffer

        try:
            # Sniff for ICMP packets
            sniff(filter="icmp", 
                  prn=self.handler, 
                  store=False,
                  stop_filter=stop_filter)

            elapsed = time.time() - start_time
            
            # ================================================================
            # SESSION SUMMARY
            # ================================================================
            print(f"\n{'═' * 75}")
            print(f"[SESSION SUMMARY]")
            print(f"{'═' * 75}")
            print(f"Duration:          {elapsed:.1f} seconds")
            print(f"Messages Received: {self.message_count}")
            
            if self.message_count > 0:
                print(f"\nMessages:")
                for rec in received_messages:
                    print(f"  #{rec['count']}: {rec['message']}")
            
            print(f"{'═' * 75}\n")
            print(f"[!] Receiver timeout reached ({elapsed:.1f}s)")

        except KeyboardInterrupt:
            elapsed = time.time() - start_time
            print(f"\n\n[!] Receiver stopped by user (CTRL+C) after {elapsed:.1f}s")
            print(f"[!] Total messages received: {self.message_count}")

        finally:
            logger.info("[!] Cleaning up receiver resources...")
            sys.exit(0)

# ============================================================================
# GET RECEIVER IP
# ============================================================================

def get_receiver_ip() -> str:
    """Get receiver's IP address"""
    import socket
    try:
        # Try to get hostname and resolve to IP
        hostname = socket.gethostname()
        my_ip = socket.gethostbyname(hostname)
        return my_ip
    except:
        # Fallback to localhost
        return "127.0.0.1"

# ============================================================================
# GET TIMEOUT FROM USER
# ============================================================================

def get_timeout_from_user() -> int:
    """Prompt user to enter listening timeout"""
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║ RECEIVER TIMEOUT CONFIGURATION                               ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    while True:
        try:
            user_input = input("[?] Enter listening duration (seconds): ").strip()
            
            if not user_input:
                print("[!] Input cannot be empty. Please enter a valid number.")
                continue
            
            timeout_value = int(user_input)
            
            if timeout_value <= 0:
                print("[!] Timeout must be positive (> 0)")
                continue
            
            if timeout_value > 3600:
                print(f"[!] Warning: Timeout is very long ({timeout_value}s > 1 hour)")
                confirm = input("Continue? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue
            
            print(f"[+] Timeout set to {timeout_value} seconds")
            return timeout_value

        except ValueError:
            print(f"[!] Invalid input: '{user_input}' is not a valid number")
            continue

        except KeyboardInterrupt:
            print("\n[!] Receiver cancelled by user")
            sys.exit(0)

        except EOFError:
            print("\n[!] Receiver cancelled (EOF)")
            sys.exit(0)

# ============================================================================
# MAIN RECEIVER ENTRY POINT
# ============================================================================

def receiver_main(timeout: Optional[int] = None) -> None:
    """Main receiver function
    
    Args:
        timeout: Optional timeout in seconds. If not provided, user is prompted
    """
    # Get receiver's IP
    my_ip = get_receiver_ip()

    # Get timeout if not provided
    if timeout is None:
        timeout = get_timeout_from_user()

    # Initialize and start receiver
    receiver = EnhancedReceiver(my_ip, timeout=timeout)
    receiver.listen()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════════╗
║ STAR-C2: RECEIVER WITH AUTO-REPLY (ENHANCED VERSION)            ║
║ Automatically replies to requests with acknowledgment           ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python receiver_enhanced.py [timeout_seconds]

Examples:
  # Without timeout (user will be prompted):
  python receiver_enhanced.py

  # With timeout (120 seconds):
  python receiver_enhanced.py 120

  # Long timeout (600 seconds = 10 minutes):
  python receiver_enhanced.py 600

How it works:
  1. Listens for ICMP REQUEST packets (type 8)
  2. Decodes the covert message using Rule-90 CA
  3. Displays: Sender IP, Orbit, Location, Temp, Voltage, Message
  4. AUTOMATICALLY sends ICMP REPLY (type 0) with acknowledgment
  5. Maintains 1:1 sequence correspondence (defeats behavioral detection)
  6. Continues until timeout is reached or CTRL+C is pressed

Features:
  ✓ Auto-reply with acknowledgment (no manual input needed)
  ✓ 1:1 REQUEST-REPLY correspondence
  ✓ Decodes Rule-90 CA encrypted messages
  ✓ Displays satellite metadata for plausibility
  ✓ Session summary with all received messages
""")
        sys.exit(1)

    # Check if timeout provided as argument
    timeout_value = None
    if len(sys.argv) >= 2:
        try:
            timeout_value = int(sys.argv[1])
            if timeout_value <= 0:
                print("[!] Error: Timeout must be positive")
                sys.exit(1)
        except ValueError:
            print(f"[!] Error: '{sys.argv[1]}' is not a valid number")
            sys.exit(1)

    # Start receiver
    receiver_main(timeout_value)
