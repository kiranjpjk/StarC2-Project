"""
CA Keystream - Rule 90 Cellular Automaton for ICMP Covert Channel Encryption

Provides stream-cipher encryption using Cellular Automata Rule 90.
The keystream is derived from a seed and XORed with plaintext.

Functions:
    rule90_step(arr): Apply one CA Rule 90 iteration
    keystream(seed_bytes, length_bits): Generate pseudo-random keystream
    ca_encode_message(msg, seed): Encrypt message with CA keystream
    ca_decode_message(enc_bytes, seed): Decrypt (same as encrypt due to XOR)
    string_to_bits(msg): Convert string to bit array
    bits_to_string(bits): Convert bit array to string

Example:
  //  >>> enc = ca_encode_message("hello", b"seed1234")
  //  >>> dec = ca_decode_message(enc, b"seed1234")
  //  >>> assert dec == "hello"

Security Note:
    - NOT cryptographically secure (CA Rule 90 is weak)
    - For covert channel obfuscation only, not production crypto
    - Use libsodium/cryptography for real encryption
"""

import numpy as np
import logging

logger = logging.getLogger(__name__)


def rule90_step(arr):
    """
    Apply Rule 90 CA step: new_bit = left_neighbor XOR right_neighbor.

    This rule produces pseudo-random-looking sequences from deterministic
    cellular automaton evolution. Used for keystream generation.

    Args:
        arr (np.ndarray): Bit array (dtype=uint8)

    Returns:
        np.ndarray: Next generation of CA state
    """
    left = np.roll(arr, 1)
    right = np.roll(arr, -1)
    return (left ^ right).astype(np.uint8)


def keystream(seed_bytes, length_bits):
    """
    Generate a pseudo-random keystream of specified length.

    Uses CA Rule 90 evolved from seed. At each step, the middle bit
    of the current state is output, then state is evolved to next gen.

    Args:
        seed_bytes (bytes): Initial seed (typically 4-8 bytes)
        length_bits (int): Number of bits to generate

    Returns:
        np.ndarray: Keystream of length_bits (dtype=uint8, values in {0,1})
    """
    try:
        # Unpack seed bytes to initial CA state
        state = np.unpackbits(np.frombuffer(seed_bytes, dtype=np.uint8))
        ks = np.zeros(length_bits, dtype=np.uint8)

        # Generate keystream by CA evolution
        for i in range(length_bits):
            # Output center bit
            ks[i] = state[len(state) // 2]
            # Evolve to next generation
            state = rule90_step(state)

        logger.debug(f"Generated {length_bits} keystream bits from {len(seed_bytes)}-byte seed")
        return ks

    except Exception as e:
        logger.error(f"Keystream generation failed: {e}")
        raise


def string_to_bits(msg: str):
    """
    Convert string to bit array.

    Args:
        msg (str): Input message

    Returns:
        np.ndarray: Bit representation (dtype=uint8)
    """
    return np.unpackbits(np.frombuffer(msg.encode(), dtype=np.uint8))


def bits_to_string(bits: np.ndarray):
    """
    Convert bit array back to string.

    Handles non-multiple-of-8 lengths by truncation.
    Ignores decode errors (replaces with placeholder).

    Args:
        bits (np.ndarray): Bit array

    Returns:
        str: Decoded string, or empty string if decode fails
    """
    try:
        # Ensure length is multiple of 8
        if len(bits) % 8 != 0:
            bits = bits[: len(bits) - (len(bits) % 8)]

        # Pack bits back to bytes
        b = np.packbits(bits)
        return b.tobytes().decode(errors="ignore")

    except Exception as e:
        logger.warning(f"Bit-to-string conversion failed: {e}")
        return ""


def ca_encode_message(msg: str, seed: bytes) -> bytes:
    """
    Encrypt a message using CA Rule 90 keystream.

    Algorithm:
        1. Convert message to bits
        2. Generate keystream from seed
        3. XOR message_bits with keystream
        4. Pack result as bytes

    Args:
        msg (str): Plain-text message
        seed (bytes): Seed for keystream generation

    Returns:
        bytes: Encrypted message (packbits format)

    Raises:
        ValueError: If seed is empty
    """
    if not msg:
        logger.warning("Empty message provided to ca_encode_message")
        return b""

    if not seed or len(seed) < 1:
        raise ValueError("Seed must be non-empty bytes")

    try:
        # Convert message to bit array
        bits = string_to_bits(msg)

        # Generate keystream
        ks = keystream(seed, len(bits))

        # XOR encryption
        enc = bits ^ ks

        # Pack to bytes
        enc_bytes = np.packbits(enc).tobytes()

        logger.debug(f"Encoded {len(msg)} chars → {len(enc_bytes)} bytes")
        return enc_bytes

    except Exception as e:
        logger.error(f"Encoding failed: {e}")
        raise


def ca_decode_message(enc_bytes: bytes, seed: bytes) -> str:
    """
    Decrypt a message using CA Rule 90 keystream.

    Note: XOR is symmetric, so decryption = encryption.

    Algorithm:
        1. Unpack encrypted bytes to bits
        2. Generate keystream from seed
        3. XOR encrypted_bits with keystream
        4. Convert result back to string

    Args:
        enc_bytes (bytes): Encrypted message bytes
        seed (bytes): Seed for keystream generation

    Returns:
        str: Decrypted message
    """
    if not enc_bytes:
        logger.warning("Empty encrypted bytes provided to ca_decode_message")
        return ""

    if not seed or len(seed) < 1:
        raise ValueError("Seed must be non-empty bytes")

    try:
        # Unpack encrypted bytes to bits
        enc_bits = np.unpackbits(np.frombuffer(enc_bytes, dtype=np.uint8))

        # Generate keystream
        ks = keystream(seed, len(enc_bits))

        # XOR decryption (same as encryption for XOR)
        dec_bits = enc_bits ^ ks

        # Convert back to string
        msg = bits_to_string(dec_bits)

        logger.debug(f"Decoded {len(enc_bytes)} bytes → '{msg}'")
        return msg

    except Exception as e:
        logger.error(f"Decoding failed: {e}")
        raise
