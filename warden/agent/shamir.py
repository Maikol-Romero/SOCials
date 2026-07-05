#!/usr/bin/env python3
"""shamir_split: split the master password into N shares, any K of which
can reconstruct it (K-of-N threshold secret sharing).

Use case: you don't want ONE person holding the socialwarden master key.
Split it 2-of-3 across CTO / CEO / SRE lead; any two can recover it.

Implementation: Shamir's Secret Sharing over GF(2^8), per-byte. Standard
polynomial interpolation. Stdlib-only (no external crypto library) — this
is a self-contained ~80 lines of GF math. For production, vetted libraries
(cryptography, pycryptodome) are preferred; this is a deliberate choice
to avoid adding a dependency to the bootstrap script.

Usage:
  # Split
  echo -n "<master-password>" | python3 shamir_split.py split --k 2 --n 3
    → prints 3 shares; distribute them to 3 people.

  # Combine (interactive: paste 2 or more shares, one per line, then Ctrl-D)
  python3 shamir_split.py combine

Format of each share: "<x-hex>:<y-bytes-hex>", one character for x (1..255),
the y polynomial evaluation as hex of raw bytes.
"""
import argparse
import os
import secrets
import sys

# ---------------------------------------------------------------------------
# Galois field GF(2^8) arithmetic (AES irreducible polynomial 0x11b).
# Generator: g=3 (x+1). 2 is NOT primitive for 0x11b; 3 is. Using 2 would
# produce a subgroup of size 51 and silently corrupt the log table.
# ---------------------------------------------------------------------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for i in range(255):
    _EXP[i] = _x
    _LOG[_x] = i
    # Multiply _x by g=3 = (x+1) in GF(2^8): (_x << 1) XOR _x, with reduction.
    hi = _x & 0x80
    new_x = ((_x << 1) & 0xff) ^ _x
    if hi:
        new_x ^= 0x1b    # add the low bits of the irreducible poly (x^8 ≡ 0x1b)
    _x = new_x
for i in range(255, 512):
    _EXP[i] = _EXP[i - 255]

def gmul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]

def gdiv(a, b):
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _EXP[(_LOG[a] + 255 - _LOG[b]) % 255]

# ---------------------------------------------------------------------------
# Split / combine
# ---------------------------------------------------------------------------
def split_bytes(secret_bytes, k, n):
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    shares = [bytearray() for _ in range(n)]
    for byte in secret_bytes:
        # random poly coeffs a_1..a_{k-1}; a_0 = the secret byte
        coeffs = [byte] + [secrets.randbits(8) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1  # x in 1..n
            y = 0
            # Horner evaluation in GF(2^8)
            for c in reversed(coeffs):
                y = gmul(y, x) ^ c
            shares[i].append(y)
    return [(i + 1, bytes(shares[i])) for i in range(n)]

def combine_bytes(shares):
    """shares: list of (x, bytes). Length must be >= k."""
    if not shares:
        raise ValueError("no shares")
    length = len(shares[0][1])
    out = bytearray(length)
    for pos in range(length):
        # Lagrange interpolation at x=0 to recover a_0
        secret_byte = 0
        for j, (xj, yj) in enumerate(shares):
            num = 1
            den = 1
            for m, (xm, _) in enumerate(shares):
                if m == j:
                    continue
                num = gmul(num, xm)         # (0 - x_m) = x_m in GF(2^8)
                den = gmul(den, xj ^ xm)    # x_j - x_m = x_j XOR x_m
            l = gdiv(num, den)
            secret_byte ^= gmul(yj[pos], l)
        out[pos] = secret_byte
    return bytes(out)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def fmt_share(x, y_bytes):
    return f"{x:02x}:{y_bytes.hex()}"

def parse_share(line):
    x_hex, y_hex = line.strip().split(":", 1)
    return int(x_hex, 16), bytes.fromhex(y_hex)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("split")
    sp.add_argument("--k", type=int, required=True)
    sp.add_argument("--n", type=int, required=True)
    sub.add_parser("combine")
    args = ap.parse_args()

    if args.cmd == "split":
        secret_bytes = sys.stdin.buffer.read()
        if not secret_bytes:
            print("ERROR: provide the secret on stdin.", file=sys.stderr); sys.exit(1)
        # Strip trailing newline from echo -n users who forgot
        secret_bytes = secret_bytes.rstrip(b"\n")
        shares = split_bytes(secret_bytes, args.k, args.n)
        print(f"# Shamir {args.k}-of-{args.n}, {len(secret_bytes)} bytes")
        print(f"# Distribute each line to a different trustee.")
        for x, y in shares:
            print(fmt_share(x, y))
        return

    if args.cmd == "combine":
        print("Paste shares, one per line. Ctrl-D to finish.", file=sys.stderr)
        shares = []
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                shares.append(parse_share(line))
            except ValueError:
                print(f"skip malformed share: {line[:40]}", file=sys.stderr)
        if len(shares) < 2:
            print("ERROR: need at least 2 shares.", file=sys.stderr); sys.exit(2)
        secret = combine_bytes(shares)
        # Emit as text; if it decodes as utf-8, print it; else raw hex.
        try:
            sys.stdout.write(secret.decode("utf-8") + "\n")
        except UnicodeDecodeError:
            sys.stdout.write(secret.hex() + "\n")


if __name__ == "__main__":
    main()
