# ca_keystream.py
# Simple 1D elementary cellular automaton keystream generator.
# Rule 30 implementation (or any 8-bit rule).
from typing import List

def rule_to_table(rule_number: int) -> dict:
    # rule_number: 0..255 (8-bit)
    table = {}
    for i in range(8):
        bit = (rule_number >> i) & 1
        # neighborhood index i corresponds to binary of neighbor (a,b,c) -> (111->7 .. 000->0)
        table[7 - i] = bit
    return table

def step(state: List[int], table: dict) -> List[int]:
    n = len(state)
    new = [0]*n
    for i in range(n):
        left = state[(i-1) % n]
        center = state[i]
        right = state[(i+1) % n]
        idx = (left << 2) | (center << 1) | right
        new[i] = table[idx]
    return new

def ca_keystream(seed_bits: List[int], rule:int, length_bytes:int) -> bytes:
    """
    seed_bits: list of 0/1 initial state (keeps CA deterministic)
    rule: integer 0..255 (Rule 30 => 30)
    length_bytes: how many bytes of keystream to generate
    """
    table = rule_to_table(rule)
    state = seed_bits.copy()
    bits_needed = length_bytes * 8
    out_bits = []
    while len(out_bits) < bits_needed:
        state = step(state, table)
        out_bits.extend(state)  # collect whole row
    # convert to bytes
    out_bits = out_bits[:bits_needed]
    b = 0
    res = bytearray()
    for i, bit in enumerate(out_bits):
        b = (b << 1) | (bit & 1)
        if (i % 8) == 7:
            res.append(b & 0xFF)
            b = 0
    return bytes(res)
