#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
# Copyright 2022, Tijl "Photubias" Deneut <@tijldeneut>
# Copyright 2026, @Banaanhangwagen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Windows DPAPI CREDHIST decryption utility."""

import sys
import argparse

try:
    import dpapick3.credhist as credhist
except ImportError:
    sys.exit("Missing dpapick3 — install with: pip install dpapick3")

SEPARATOR = "-" * 60


# -----------------------------
# Algorithm name resolution
# -----------------------------
HASH_ALG_MAP = {
    0x8009: "SHA-1",
    0x8004: "SHA-1",
    0x800E: "SHA-512",
}

CIPHER_ALG_MAP = {
    0x6603: "3DES",
    0x6610: "AES-128",
}


def resolve_alg_name(value, mapping, prefix):
    if value is None:
        return f"{prefix}(None)"
    return mapping.get(value, f"{prefix}(UNKNOWN:{hex(value)})")


def safe_hex(data):
    if data is None:
        return None
    try:
        return data.hex()
    except Exception:
        return None


# -----------------------------
# Formatting
# -----------------------------
def format_entry(entry):
    rev = getattr(entry, "revision", None)
    sid = getattr(entry, "userSID", None)
    guid = getattr(entry, "guid", None)
    rounds = getattr(entry, "rounds", None)
    sha_len = getattr(entry, "shaHashLen", None)
    nt_len = getattr(entry, "ntHashLen", None)

    hash_algo_id = getattr(getattr(entry, "hashAlgo", None), "algnum", None)
    cipher_algo_id = getattr(getattr(entry, "cipherAlgo", None), "algnum", None)

    hash_algo = resolve_alg_name(hash_algo_id, HASH_ALG_MAP, "HASH")
    cipher_algo = resolve_alg_name(cipher_algo_id, CIPHER_ALG_MAP, "CIPHER")

    iv = safe_hex(getattr(entry, "iv", None))
    enc = safe_hex(getattr(entry, "encrypted", None))

    lines = [
        "CredHist entry",
        f"\trevision   = {rev}",
        f"\thashAlgo   = {hash_algo}",
        f"\tcipherAlgo = {cipher_algo}",
        f"\trounds     = {rounds}",
        f"\tshaHashLen = {sha_len}",
        f"\tntHashLen  = {nt_len}",
        f"\tuserSID    = {sid}",
        f"\tguid       = {guid}",
        f"\tiv         = {iv}",
        f"\tencrypted  = {enc}",
    ]

    pwdhash = getattr(entry, "pwdhash", None)
    ntlm = getattr(entry, "ntlm", None)

    if pwdhash is not None:
        lines.append(f"\t[+] pwdhash = {safe_hex(pwdhash)}")
    if ntlm is not None:
        lines.append(f"\t[+] NTLM    = {safe_hex(ntlm)}")

    return "\n".join(lines)


# -----------------------------
# Credhist hash builder
# -----------------------------
def build_credhist_hash(entry):
    try:
        rev = getattr(entry, "revision", 0)
        sid = getattr(entry, "userSID", "")
        rounds = getattr(entry, "rounds", 0)
        sha_len = getattr(entry, "shaHashLen", 0)
        nt_len = getattr(entry, "ntHashLen", 0)

        hash_algo_id = getattr(getattr(entry, "hashAlgo", None), "algnum", None)
        cipher_algo_id = getattr(getattr(entry, "cipherAlgo", None), "algnum", None)

        iv = safe_hex(getattr(entry, "iv", b""))
        enc = safe_hex(getattr(entry, "encrypted", b""))

        return (
            f"$credhist$*{rev}*{sid}*"
            f"{hex(hash_algo_id if hash_algo_id else 0)}*"
            f"{hex(cipher_algo_id if cipher_algo_id else 0)}*"
            f"{rounds}*{iv}*{sha_len}*{nt_len}*{enc}"
        )
    except Exception:
        return None


# -----------------------------
# CLI
# -----------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Decrypt a Windows DPAPI CREDHIST file.",
        epilog="Without --password or --pwdhash, only structure is shown."
    )

    parser.add_argument("credhist", help="Path to the CREDHIST file")
    parser.add_argument("--password", help="Current user password")
    parser.add_argument("--pwdhash", help="SHA-1 of current password (hex)")

    return parser.parse_args()


def load_file(path):
    try:
        return open(path, "rb").read()
    except Exception as e:
        sys.exit(f"[-] Failed to read file: {e}")


def try_decrypt(cred, args):
    if args.pwdhash:
        try:
            cred.decryptWithHash(bytes.fromhex(args.pwdhash))
        except ValueError:
            sys.exit("[-] Invalid --pwdhash hex string")
    elif args.password:
        cred.decryptWithPassword(args.password)
    else:
        print("[!] No password supplied — showing structure only.")


def main():
    args = parse_args()

    data = load_file(args.credhist)
    cred = credhist.CredHistFile(data)

    if len(cred.entries_list) == 0:
        sys.exit("[-] No entries found in CREDHIST file.")

    try_decrypt(cred, args)

    entries = cred.entries_list

    print(SEPARATOR)

    for i, entry in enumerate(entries, 1):
        print(f"Entry {i}:")
        print(format_entry(entry))

        credhist_hash = build_credhist_hash(entry)
        if credhist_hash:
            print("\n[!] Extracted hash:", credhist_hash)

        print(SEPARATOR)

    print(f"\n[!] {len(entries)} CREDHIST entries processed.")


if __name__ == "__main__":
    main()
