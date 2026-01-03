#!/usr/bin/python3
# -*- coding: utf-8 -*-
r'''
Copyright 2026, Tijl "Photubias" Deneut <@tijldeneut>
Copyright 2026, Banaanhangwagen <@banaanhangwagen>
GNU GENERAL PUBLIC LICENSE - Version 3
This script provides offline decryption of Chromium based browser user data: Google Chrome, Edge Chromium and Opera

Update 2025-05: clean-up code
Update 2025-06: make it compatible with AppBoundEncryption
Update 2025-08: code clean-up and minor updates
Update 2025-11: code refactoring and adding flag "v3"
Update 2026-01: code refactoring + adding CNG-key for v3 decryption
'''
import argparse
import os
import json
import base64
import sqlite3
import re
import sys
import struct

from Crypto.Cipher import AES, ChaCha20_Poly1305
from termcolor import colored

# Import dpapick3 with error handling
try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    sys.exit(colored("[-] Critical Error: The 'dpapick3' library is missing. "
                     "Please install it via `pip install dpapick3`", "red"))

# ============================================================================
# CONSTANTS
# ============================================================================
DPAPI_PREFIX = b'\x01\x00\x00\x00'
# DPAPI_PREFIX_LENGTH = 5             # Length of "DPAPI" text prefix in base64
APPBOUND_PREFIX = b'\x76\x32\x30'   # "v20"
APPB_PREFIX_LENGTH = 4              # Length of "APPB" prefix
V10_PREFIX = b'v10'

# Static keys for third-stage app_bound_encryption-key derivation -
# see: https://github.com/tijldeneut/diana/pull/6
AES_STATIC_KEY = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
CHACHA20_STATIC_KEY = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

# Default empty password SHA1 hash
EMPTY_PASSWORD_HASH = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

# ============================================================================
# FILE PARSING
# ============================================================================
def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'{hex_part:<{width * 3}}  {ascii_part}')
    return '\n'.join(lines)


def load_json_file(filepath):
    with open(filepath, "r") as f:
        return json.load(f)


def decode_base64_key(key_b64, prefix_len=5):   # Skip "DPAPI" prefix
    return base64.b64decode(key_b64)[prefix_len:]

    
def parse_local_state(filepath, verbose=True):
    """Extract encrypted_key/app_bound_encrypted_key and browser-version from Local State file."""
    try:
        data = load_json_file(filepath)
        os_crypt = data.get("os_crypt", {})

        # Extract and decode encrypted_key
        encrypted_key_b64 = os_crypt.get("encrypted_key")
        if not encrypted_key_b64:
            sys.exit(colored(f"[-] Error: 'encrypted_key' not found in {filepath}", "red"))
        local_state_blob = blob.DPAPIBlob(decode_base64_key(encrypted_key_b64))

        # Extract and decode app_bound_encrypted_key if present
        abe_system_blob = None
        app_bound_encrypted_key_b64 = os_crypt.get("app_bound_encrypted_key")
        if app_bound_encrypted_key_b64:
            abe_data = base64.b64decode(app_bound_encrypted_key_b64).strip(b'\x00')
            abe_system_blob = blob.DPAPIBlob(abe_data[APPB_PREFIX_LENGTH:])

        if verbose:
            print(colored("[INFO] Parsing \'Local State\'", "yellow"))
            print(f"    [+] GUID encrypted_key :           {local_state_blob.mkguid}")
            if abe_system_blob:
                print(f"    [+] GUID app_bound_encrypted_key : {abe_system_blob.mkguid}")

        # Extract browser version
        version = data.get ('variations_permanent_consistency_country', [None])[0]
        if verbose and version:
            print(f"    [+] Browser version:               {version}")

        return local_state_blob, abe_system_blob, version

    except Exception as e:
        sys.exit(colored(f"[-] Error reading Local State file: {e}", 'red'))


def parse_sqlite_table(filepath, query, blob_columns=None, guid_list=None):
    """Generic SQLite parser with optional DPAPI blob detection."""
    results = []
    # guid_list = guid_list or []
    if guid_list is None:
        guid_list = []

    try:
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()

        for row in rows:
            if blob_columns:
                for idx in blob_columns:
                    val = row[idx]
                    if val and val.startswith(DPAPI_PREFIX):
                        parsed_blob = blob.DPAPIBlob(val)
                        if parsed_blob.mkguid not in guid_list:
                            guid_list.append(parsed_blob.mkguid)
            results.append(tuple(row))

        return results, guid_list
    except sqlite3.Error as e:
        print(colored(f"[-] Error reading Login Data: {e}", 'red'))
        return results, guid_list


def parse_login_data(filepath, guid_list):
    """Extract login credentials from Login Data SQLite database."""
    print(colored("[INFO] Parsing \'Login Data\'", "yellow"))
    logins, guid_list = parse_sqlite_table(filepath, 'SELECT origin_url, username_value, password_value, id FROM logins', blob_columns=[2], guid_list=guid_list)
    print(f"[INFO] Found {len(logins)} credential(s)")
    return logins, guid_list


def parse_notes(filepath, guid_list):
    """Extract password notes from Login Data database."""
    notes, guid_list = parse_sqlite_table(filepath, 'SELECT value FROM password_notes', blob_columns=[0], guid_list=guid_list)
    print(f"[INFO] Found {len(notes)} note(s)")
    return notes, guid_list


def parse_deleted_logins(filepath):
    """Extract deleted login (bonus feature)."""
    try:
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT origin_domain, username_value FROM stats')
            deleted = cursor.fetchall()
        if deleted:
            print(colored("\n[BONUS] Deleted Login Statistics:", 'yellow'))
            for domain, username in deleted:
                print(f"    {domain}\t{username}")
    except sqlite3.Error:
        pass        # Stats table may not exist


# ============================================================================
# MASTERKEY OPERATIONS
# ============================================================================
def extract_dpapi_system_key(system_hive, security_hive, verbose=False):
    """Extract DPAPI_SYSTEM key from registry hives."""
    try:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(security_hive, system_hive)
        dpapi_system = secrets.get('DPAPI_SYSTEM', {}).get('CurrVal')
        if dpapi_system and verbose:
            print(colored(f"    [+] Stage 0 - Extracted DPAPI_SYSTEM key from registry:", "cyan"))
            print(colored(f"{hexdump(dpapi_system)}",))
        return dpapi_system

    except Exception as e:
        print(colored(f"[-] Stage 0 - Error extracting DPAPI_SYSTEM: {e}", "red"))
        return None


def load_user_masterkeys(mkfile_path, sid=None, password=None, pwdhash=None, verbose=False):
    """Load and decrypt UserMasterkeys using provided credentials."""
    mkp = masterkey.MasterKeyPool()

    # Load masterkey files
    if os.path.isfile(mkfile_path):
        # mkp.addMasterKey(open(mkfile_path, 'rb').read())
        with open(mkfile_path, 'rb') as f:
            mkp.addMasterKey(f.read())
    else:
        mkp.loadDirectory(mkfile_path)
        if verbose:
            print(f'    [+] Loaded {len(mkp.keys)} UserMasterkey file(s)')

    # Decrypt with user credentials
    if sid and (password or pwdhash):
        if verbose:
            print('    [+] Trying provided password on each UserMasterkey')
        if password:
            mkp.try_credential(sid, password)
        else:
            mkp.try_credential_hash(sid, pwdhash)

    decrypted_keys = []
    for mk_list in mkp.keys.values():
        for mk in mk_list:
            if mk.decrypted:
                key = mk.get_key()
                guid = mk.guid.decode()
                if (guid, key) not in decrypted_keys:
                    decrypted_keys.append((guid, key))
                        #if verbose:
                        #    print(colored(f"        [*] Trying user_MK: {guid}", "magenta"))
    return mkp, decrypted_keys


def load_system_masterkeys(system_mk_folder, dpapi_system_key, verbose=False):
    """Load and decrypt system masterkeys"""
    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(system_mk_folder)
    mkp.addSystemCredential(dpapi_system_key)

    system_masterkeys = []
    if mkp.try_credential_hash(None, None) > 0:
        for mk_list in mkp.keys.values():
            for mk in mk_list:
                if mk.decrypted:
                    system_masterkeys.append((mk.guid.decode(), mk.get_key()))
                    # if verbose:
                    #     print(colored(f"           [*] Decrypted SystemMasterkey: {mk.guid.decode()}", "magenta"))
    return system_masterkeys


# ============================================================================
# DECRYPTION OPERATIONS
# ============================================================================
def detect_encryption_type(encrypted_data):
    """Detect the encryption type used for the data."""
    if not encrypted_data:
        return 'UNKNOWN'
    if encrypted_data.startswith(DPAPI_PREFIX):
        return 'DPAPI'
    if encrypted_data.startswith(APPBOUND_PREFIX):
        return 'APPBOUND'
    if encrypted_data.startswith(V10_PREFIX):
        return 'V10'
    return 'UNKNOWN'


def decrypt_dpapi_blob(parsed_blob, masterkey):
    """Decrypt a DPAPI blob using a masterkey."""
    try:
        if parsed_blob.decrypt(masterkey):
            return parsed_blob.cleartext
    except Exception as e:
        print(colored(f"[-] Failed to decrypt blob: {e}", "red"))
    return None


def decrypt_chrome_password(encrypted_data, bme_key, abe_key=None, masterkeys=None, verbose=False):
    enc_type = detect_encryption_type(encrypted_data)

    if enc_type == 'DPAPI':             # Decrypt legacy DPAPI-encrypted password
        if masterkeys:
            dpapi_blob = blob.DPAPIBlob(encrypted_data)
            for mk in masterkeys:
                dpapi_blob.decrypt(mk)
                if dpapi_blob.decrypted:
                    return dpapi_blob.cleartext.decode(errors='ignore')

    elif enc_type == 'APPBOUND' and abe_key:
        try:
            iv = encrypted_data[3:15]
            payload = encrypted_data[15:-16]
            tag = encrypted_data[-16:]

            cipher = AES.new(abe_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(payload, tag)
            return decrypted.decode(errors='ignore')
        except ValueError as e:
            if verbose:
                print(colored(f"[-] Error decrypting v20 password: {e}", 'red'))

    elif enc_type == 'V10' and bme_key:
        try:
            iv = encrypted_data[3:15]
            payload = encrypted_data[15:]

            cipher = AES.new(bme_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)
            return decrypted[:-16].decode(errors='ignore')

        except Exception:
            if verbose:
                print(colored("[-] Error decrypting v10 password", 'red'))
    return None


def decrypt_browser_master_encryption_key(local_state_blob, masterkeys, verbose=False):
    """
    Decrypt the Browser Master Encryption (BME) key from Local State.
    """
    print(colored('\n[INFO] Extracting Browser_Master_Encryption-key from encrypted_key in Local State...', 'yellow'))

    for mk in masterkeys:
        bme_key = decrypt_dpapi_blob(local_state_blob, mk)
        if bme_key:
            if verbose:
                print(colored(f'    [+] BME_key (hex): \n{hexdump(bme_key)}', ))
            return bme_key
    return None


def decrypt_abe_stage1_with_system_key(abe_system_blob, system_masterkeys, verbose=False):
    """
    Stage 1: Decrypt app_bound_encrypted_key using SystemMasterkey.
    """
    if verbose:
        print(colored('    [+] Stage 1 - Decrypting app_bound_encrypted_key with SystemMasterkey', "cyan"))

    for guid, system_mk in system_masterkeys:
        if verbose:
            print(colored(f"         [*] Trying SystemMasterkey: {guid}", "magenta"))
        decrypted = decrypt_dpapi_blob(abe_system_blob, system_mk)
        if decrypted:
            abe_user_blob = blob.DPAPIBlob(decrypted)
            if verbose:
                print(colored(f"         [+] Success! The last SystemMasterkey decrypted the app_bound_encryption from Local State", ))
                print(colored(f"         [+] Parsing new blob...", ))
                print(colored(f"         [+] GUID of UserMasterkey detected: {abe_user_blob.mkguid}", ))
            return abe_user_blob
    return None


def decrypt_abe_stage2_with_user_key(abe_user_blob, masterkeys, verbose=False):
    """
    Stage 2: Decrypt abe_user_blob using new UserMasterkey.
    """
    if verbose:
        print(colored(f'    [+] Stage 2 - Decrypting new app_bound_blob with UserMasterkey', "cyan"))

    for mk in masterkeys:
        abe_encrypted_key = decrypt_dpapi_blob(abe_user_blob, mk)
        if abe_encrypted_key:
            if verbose:
                print(colored(f'         [+] Success!', ))
                print(colored(f'         [+] Got encrypted_ABE-key: \n{hexdump(abe_encrypted_key)}', ))
            return abe_encrypted_key
    return None


def extract_cng_key_from_directory(dirpath, args, verbose=False):
    """
    Implements extraction of new CNG-key:
    - Scan directory for UTF16 'Google Chromekey1'
    - Locate DPAPI block pair
    - Decrypt second block using dpapick with SYSTEM master keys
    - Validate KDBM header
    - Return last 32 bytes
    """
    if verbose:
        print(colored(f"               [*] Starting CNG-key extraction from: {dirpath}",))

    # Check if directory exists
    if not os.path.exists(dirpath):
        print(colored(f"               [!] Directory does not exist: {dirpath}", "red"))
        return None

    if not os.path.isdir(dirpath):
        print(colored(f"               [!] Path is not a directory: {dirpath}", "red"))
        return None

    search_utf16 = "Google Chromekey1".encode("utf-16le")
    private_key_utf16 = "Private Key".encode("utf-16le")

    dpapi_marker = bytes.fromhex(
        "01 00 00 00 D0 8C 9D DF 01 15 D1 11 8C 7A 00 C0"
    )

    candidate_file = None
    file_bytes = None

    # Find candidate file
    try:
        files = os.listdir(dirpath)
        if verbose:
            print(colored(f"               [*] Scanning {len(files)} items in directory",))
    except Exception as e:
        print(colored(f"[-] Error listing directory: {e}", "red"))
        return None

    for name in files:
        path = os.path.join(dirpath, name)
        if not os.path.isfile(path):
            continue

        try:
            with open(path, "rb") as f:
                buf = f.read()

            if search_utf16 in buf:
                candidate_file = path
                file_bytes = buf
                print(colored(f"               [+] Found \"Google Chromekey1\" in: {path}", "green"))
                break
        except Exception as e:
            if verbose:
                print(colored(f"[-] Error reading file {name}: {e}", "red"))
            continue

    if not candidate_file:
        print(colored("               [!] No file containing 'Google Chromekey1' found", "red"))
        return None

    # Extract DPAPI blocks
    offsets = []
    pos = 0
    while True:
        try:
            idx = file_bytes.index(dpapi_marker, pos)
            offsets.append(idx)
            if verbose:
                print(colored(f"               [*] Found DPAPI marker at offset: {idx}",))
            pos = idx + 1
        except ValueError:
            break

    if len(offsets) < 2:
        print(colored(f"               [-] Need at least 2 DPAPI blocks, found: {len(offsets)}", "red"))
        return None

    second_block = file_bytes[offsets[1]:]

    if private_key_utf16 not in second_block:
        print(colored("               [-] 'Private Key' string not found in second DPAPI block", "red"))
        return None

    if verbose:
        print(colored("               [+] Found 'Private Key' in second block", "green"))

    # Parse DPAPI blob
    try:
        dpapi_blob = blob.DPAPIBlob(second_block)
    except Exception as e:
        print(colored(f"               [-] Error parsing DPAPI blob: {e}", "red"))
        return None

    # Load SystemMasterkeys
    mkp = masterkey.MasterKeyPool()
    system_masterkey_path = None
    if hasattr(args, 'systemmasterkey') and args.systemmasterkey:
        system_masterkey_path = args.systemmasterkey
    elif hasattr(args, 'y') and args.y:
        system_masterkey_path = args.y
    elif hasattr(args, 'system_mkfile') and args.system_mkfile:
        system_masterkey_path = args.system_mkfile
    else:
        print(colored("[-] No system master key directory specified (need --systemmasterkey or -y)", "red"))
        return None

    try:
        mkp.loadDirectory(system_masterkey_path)
        if verbose:
            print(colored(f"               [*] Loaded SystemMasterkeys from: {system_masterkey_path}",))
    except Exception as e:
        print(colored(f"               [-] Error loading system master keys: {e}", "red"))
        return None

    # Load system credentials for decrypting system master keys
    try:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(args.security, args.system)
        mkp.addSystemCredential(secrets["DPAPI_SYSTEM"]["CurrVal"])
        mkp.try_credential_hash(None, None)

    except Exception as e:
        print(colored(f"               [-] Error loading SystemMasterkeys: {e}", "red"))
        return None

    print(colored(f"               [+] CNG-blob references following SystemMasterKey GUID: {dpapi_blob.mkguid}",))

    # Get master keys using the GUID
    master_keys = mkp.getMasterKeys(dpapi_blob.mkguid.encode())

    if not master_keys:
        print(colored(f"[-] No master keys found for GUID: {dpapi_blob.mkguid}", "red"))
        if verbose:
            print(colored(f"[*] Available system master key GUIDs:", "cyan"))
            for guid in mkp.keys.keys():
                print(colored(f"    - {guid}", "cyan"))
        return None

    if verbose:
        print(colored(f"               [*] Found {len(master_keys)} SystemMasterkey(s) for this GUID",))

    entropy = b"xT5rZW5qVVbrvpuA\x00"

    # Try to decrypt with the matched master keys
    for mk in master_keys:
        if not mk.decrypted:
            if verbose:
                print(colored(f"[*] SystemMasterkey not decrypted, skipping", "yellow"))
            continue

        if verbose:
            print(colored(f"               [*] Trying to decrypt DPAPI blob with SystemMasterkey",))

        dpapi_blob.decrypt(mk.get_key(), entropy)

        if dpapi_blob.decrypted:
            clear = dpapi_blob.cleartext
            if verbose:
                print(colored(f"               [+] Successfully decrypted DPAPI-blob ({len(clear)} bytes)",))
                print(hexdump(clear))

            if clear.startswith(b"KDBM"):
                key = clear[-32:]
                print(colored("               [+] Extracted CNG-key (32 bytes):", "green"))
                print(hexdump(key))

                return key
            else:
                print(colored(f"               [-] Warning! Decrypted blob does not start with KDBM-header: {clear[:4].hex()}", "red"))
                if verbose:
                    print(hexdump(clear[:64]))

    print(colored(f"[-] Unable to decrypt DPAPI blob with available SystemMasterkeys", "red"))
    return None


def decrypt_abe_stage3_with_static_keys(abe_encrypted_key, args, verbose=False):
    """
    Stage 3: Decrypt app_bound_encrypted_key.
    """
    if verbose:
        # print(colored('    [+] Stage 3 - Checking for CNG ChromeKey1 path', ))
        print(colored('    [+] Stage 3 - Decrypt app_bound_encrypted_key', "cyan"))

    try:
        # Parse header
        header_len = struct.unpack('<I', abe_encrypted_key[:4])[0]
        header_end = 4 + header_len
        header = abe_encrypted_key[4:header_end].strip(b'\x02').decode(errors='ignore')

        if verbose:
            print(colored(f'         [+] Found header in encrypted_ABE-key: "{header}"', ))

        # Parse content
        content_len = struct.unpack('<I', abe_encrypted_key[header_end:header_end + 4])[0]
        content_start = header_end + 4
        content = abe_encrypted_key[content_start:content_start + content_len]

        # Handle unversioned format (some Edge versions)
        if content_len == 32:
            if verbose: print(colored('         [+] Version flag not found, using raw key', "red"))
            return content

        # Determine version and decrypt
        version = int(content[0])
        data = content[1:]
        decrypted_key = None

        if verbose:
            print(colored(f'         [+] Detected ABE_key version: {version}', ))

        if version in (1, 2):
            # Format: IV(12) | Ciphertext(32) | Tag(16)
            iv = data[:12]
            ciphertext = data[12:44]
            tag = data[44:60]

            if version == 1:
                if verbose: print('         [+] Using AES-GCM with static key to do final decryption')
                cipher = AES.new(AES_STATIC_KEY, AES.MODE_GCM, nonce=iv)
            else:
                if verbose: print('         [+] Using ChaCha20-Poly1305 with static key to do final decryption')
                cipher = ChaCha20_Poly1305.new(key=CHACHA20_STATIC_KEY, nonce=iv)

            decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)


        elif version == 3:
            if verbose:
                print('         [+] Using extra CNG-key for version 3 decryption')

            # Check if CNG directory argument is provided
            if not hasattr(args, 'cng') or not args.cng:
                print(colored('    [!] Stage 3 - No CNG-directory specified (use --cng argument)', 'red'))
                return None

            cng_key = extract_cng_key_from_directory(args.cng, args, verbose)

            if not cng_key:
                if verbose:
                    print(colored('    [!] Stage 3 - Failed to extract CNG-key', 'red'))
                return None

            if len(cng_key) != 32:
                print(colored(f'    [-] Stage 3 - Invalid CNG key length: {len(cng_key)} (expected 32)', 'red'))
                return None

            # Format: EncAES(32) | IV(12) | Ciphertext(32) | Tag(16)
            encrypted_aes_key = data[:32]
            iv = data[32:44]
            ciphertext = data[44:76]
            tag = data[76:92]

            # Step 1: Decrypt the AES key using CNG-key with AES-CBC
            cipher_cbc = AES.new(cng_key, AES.MODE_CBC, iv=b"\x00" * 16)
            decrypted_aes_key = cipher_cbc.decrypt(encrypted_aes_key)

            if verbose:
                print("               [+] Decrypted encrypted_ABE_key:")
                print(hexdump(decrypted_aes_key))

            # Step 2: XOR with static key
            xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
            xored_aes_key = bytes(a ^ b for a, b in zip(decrypted_aes_key, xor_key))

            if verbose:
                print("               [+] Applying XOR:")
                print(hexdump(xored_aes_key))

            # Step 3: Use the derived key to decrypt the final ciphertext with AES-GCM
            cipher_gcm = AES.new(xored_aes_key, AES.MODE_GCM, nonce=iv)
            decrypted_key = cipher_gcm.decrypt_and_verify(ciphertext, tag)

        else:
            if verbose:
                print(f'    [-] Stage 3 - Unknown ABE_key version: {version}')
                print(colored('    [!] Using fallback: last 32 bytes as key', 'yellow'))

            decrypted_key = abe_encrypted_key[-32:]

        # final print and return
        if verbose:
                print(colored(f'               [+] Final decrypted ABE_key: \n{hexdump(decrypted_key)}', ))
        return decrypted_key

    except Exception as e:
        if verbose:
            print(colored(f'    [-] Stage 3 - Error parsing ABE_key blob: {e}', 'red'))
            print(colored('    [!] Using fallback: last 32 bytes as key', 'yellow'))
        return abe_encrypted_key[-32:]


def decrypt_app_bound_encryption_key(abe_system_blob, system_hive, security_hive,
                                     system_mk_folder, user_masterkeys, args, verbose=False):
    """
    Complete 3-stage App-Bound Encryption key decryption process.
    """
    print(colored('\n[INFO] Processing App-Bound Encryption (3-stage decryption)', 'yellow'))

    # Stage 0: Extract DPAPI_SYSTEM from registry
    dpapi_system = extract_dpapi_system_key(system_hive, security_hive, verbose)
    if not dpapi_system:
        return None

    # Load system masterkeys
    system_masterkeys = load_system_masterkeys(system_mk_folder, dpapi_system, verbose)
    if not system_masterkeys:
        return None

    # Stage 1: Decrypt with system masterkey
    abe_user_blob = decrypt_abe_stage1_with_system_key(abe_system_blob, system_masterkeys, verbose)
    if not abe_user_blob:
        return None

    # Stage 2: Decrypt with user masterkey
    abe_encrypted_key = decrypt_abe_stage2_with_user_key(abe_user_blob, user_masterkeys, verbose)
    if not abe_encrypted_key:
        return None

    # Stage 3: Decrypt with static keys
    abe_key = decrypt_abe_stage3_with_static_keys(abe_encrypted_key, args, verbose)

    return abe_key


# ============================================================================
# OUTPUT
# ============================================================================
def decrypt_and_display_logins(logins, bme_key, abe_key, masterkeys, csvfile=None, verbose=False):
    """Decrypt and display login credentials."""
    print(colored('\n[INFO] Decrypting logins...', 'yellow'))

    decrypted_count = 0
    csv_data = []

    for url, username, pwd_blob, login_id in logins:
        password = decrypt_chrome_password(pwd_blob, bme_key, abe_key, masterkeys, verbose)
        version = pwd_blob[:3].decode('ascii', errors='ignore') if pwd_blob else 'N/A'

        print(f"\nID:        {login_id}")
        print(f"Version:   {version}")
        print(f"URL:       {url}")
        print(f"Username:  {username}")
        print(f"Password:  {password}")
        print('*' * 50)

        if password is not None:
            decrypted_count += 1

        if csvfile:
            csv_data.append(f"{login_id};{version};{url};{username};{password}")

    # Export to CSV if requested
    if csvfile:
        output_file = f'credentials_{csvfile}'
        with open(output_file, 'w') as f:
            f.write("ID;Version;URL;Username;Password\n")
            f.write('\n'.join(csv_data))
        print(colored(f'\n[INFO] Exported to: {output_file}', 'green'))

    # if csvfile:
    #     with open(f'credentials_{csvfile}', 'w') as f:
    #         f.write("ID;Version;URL;Username;Password\n")
    #         f.write('\n'.join(csv_data))

    print(colored(f'\n[INFO] Decrypted {decrypted_count}/{len(logins)} credentials', 'yellow'))
    return decrypted_count


def decrypt_and_display_notes(notes, bme_key, abe_key, masterkeys, csvfile=None, verbose=False):
    """Decrypt and display password notes."""
    print(colored('\n[INFO] Decrypting notes...', 'yellow'))
    print('*' * 50)

    decrypted_count = 0
    csv_data = []

    for note_blob in notes:
        note_text = decrypt_chrome_password(note_blob, bme_key, abe_key, masterkeys, verbose)

        if verbose:
            print(f"Note: {note_text}")
            print('*' * 50)

        if note_text is not None:
            decrypted_count += 1
            csv_data.append(note_text)

    # Export to CSV if requested
    if csvfile:
        output_file = f'notes_{csvfile}'
        with open(output_file, 'w') as f:
            f.write('Note\n')
            f.write('\n'.join(csv_data))
        print(colored(f'\n[INFO] Exported to: {output_file}', 'green'))

    # if csvfile:
    #     with open(f'notes_{csvfile}', 'w') as f:
    #         f.write('Note\n')
    #         f.write('\n'.join(csv_data))

    print(colored(f'[INFO] Decrypted {decrypted_count}/{len(notes)} notes', 'yellow'))
    return decrypted_count


# ============================================================================
# VALIDATION & SETUP
# ============================================================================
def setup_argument_parser():
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(description="Chrome Offline Password Recovery (Ch.O.P.R)")
    parser.add_argument('-t', '--statefile', default='Local State', help='Local State file path')
    parser.add_argument('-l', '--loginfile', help='Login Data SQLite database path')
    parser.add_argument('-m', '--mkfile', required=True, help='UserMasterkey folder path')
    parser.add_argument('-y', '--systemmasterkey', help='SystemMasterkey folder path')
    parser.add_argument('-s', '--sid', help='User SID')
    parser.add_argument('-p', '--password', help='User password')
    parser.add_argument('-a', '--pwdhash', help='SHA1 password hash (hex)')
    parser.add_argument('-e', '--system', help='SYSTEM registry hive')
    parser.add_argument('-u', '--security', help='SECURITY registry hive')
    parser.add_argument('-o', '--export', help='Export to CSV filename')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--cng', help='Directory to scan for Chrome CNG key blobs')

    return parser


def validate_file_paths(args):
    """Validate that all provided file paths exist."""
    checks = [
        (args.statefile, os.path.isfile),
        (args.loginfile, os.path.isfile),
        (args.system, os.path.isfile),
        (args.security, os.path.isfile),
        (args.systemmasterkey, os.path.isdir),
        (args.mkfile, os.path.isdir)
    ]
    for path, check in checks:
        if path and not check(path):
            sys.exit(colored(f"[-] File/folder not found: {path}", "red"))


def parse_sid_from_masterkey_path(mkfile_path):
    """Extract user SID from UserMasterkey folder path."""
    match = re.search(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", mkfile_path)
    return match.group() if match else None


def display_usage_information():
    print(colored('[INFO] Welcome to the Ch.O.P.R.! You\'ll need:', 'yellow'))
    print(f"  Local State, Login Data, UserMasterkeys folder + SID, SystemMasterkeys folder, SYSTEM, SECURITY and the user password/Cachedata-key")

    print(colored("[INFO] File locations:", 'yellow'))
    print(f"  Local State:      %appdata%\\Local\\{{Google/Microsoft}}\\{{Chrome/Edge}}\\User Data\\Local State")
    print(f"  Login Data:       %appdata%\\Local\\{{Google/Microsoft}}\\{{Chrome/Edge}}\\User Data\\Default\\Login Data")
    print(f"  UserMasterkeys:   %appdata%\\Roaming\\Microsoft\\Protect\\S-1-5-21...-folder")
    print(f"  SystemMasterkeys: %Windows%\\System32\\Microsoft\\Protect\\S-1-5-18\\User-folder")
    print(f"  Cachedata:        %Windows%\\System32\\config\\systemprofile\\AppData\\local\\microsoft\\windows\\CloudAPCache\\MicrosoftAccount\\Cachedata")
    print(f"  CNG:              %ProgramData%\\Microsoft\\Crypto\\SystemKeys-folder")


def prepare_arguments(args):
    """Process and prepare arguments with defaults and auto-detection."""
    # Clean mkfile path
    if args.mkfile:
        args.mkfile = args.mkfile.replace('*', '')

        # Auto-detect SID if not provided
        if not args.sid:
            args.sid = parse_sid_from_masterkey_path(args.mkfile)
            if args.sid:
                print(colored(f"\n[INFO] Auto-detected SID: {args.sid}", 'yellow'))

        # Use empty password hash if no credentials provided
        if args.sid and not args.password and not args.pwdhash:
            args.pwdhash = EMPTY_PASSWORD_HASH
            print(colored(f"[INFO] No password given. Using empty password hash", 'yellow'))

    # Convert password hash to bytes
    if args.pwdhash:
        try:
            args.pwdhash = bytes.fromhex(args.pwdhash)
        except ValueError:
            sys.exit(colored(f"[-] Invalid hex string for pwdhash", "red"))

    return args


def check_abe_requirements(args, abe_system_blob):
    """Check if all requirements for ABE decryption are met."""
    if not abe_system_blob:
        return False

    has_requirements = all([
        args.system,
        args.security,
        args.systemmasterkey
    ])

    if not has_requirements and args.verbose:
        print(colored("\n[INFO] App-Bound Encryption detected but missing requirements:", "yellow"))
        if not args.system:
            print("    [-] SYSTEM registry hive not provided (-e)")
        if not args.security:
            print("    [-] SECURITY registry hive not provided (-u)")
        if not args.systemmasterkey:
            print("    [-] SystemMasterkey folder not provided (-y)")
        print("    [!] ABE decryption will be skipped for v20 passwords")

    return has_requirements


# ============================================================================
# MAIN PROGRAM FLOW
# ============================================================================

def main():
    # ========================================================================
    # PHASE 1: Setup & Validation
    # ========================================================================
    args = setup_argument_parser().parse_args()
    # args = parser.parse_args()

    # Display usage info if verbose
    if args.verbose:
        display_usage_information()

    # Prepare and validate arguments
    args = prepare_arguments(args)
    validate_file_paths(args)

    # ========================================================================
    # PHASE 2: Parse Input Files
    # ========================================================================

    # Parse "Local State"
    local_state_blob, abe_system_blob, _ = parse_local_state(args.statefile, args.verbose)
    guid_list = [local_state_blob.mkguid]

    # if args.verbose:
    #     print(colored(f"    [DBG] local_state_blob (object): {local_state_blob}", "cyan"))
    #     if abe_system_blob:
    #         print(colored(f"    [DBG] abe_system_blob (object): {abe_system_blob}", "cyan"))

    # Parse Login Data database
    if not args.loginfile:
        sys.exit(colored('[-] Error: No Login Data file provided (-l)', 'red'))

    logins, guid_list = parse_login_data(args.loginfile, guid_list)
    notes, guid_list = parse_notes(args.loginfile, guid_list)

    # ========================================================================
    # PHASE 3: Load and Decrypt Masterkeys
    # ========================================================================

    mkp, decrypted = load_user_masterkeys(
        args.mkfile, args.sid, args.password, args.pwdhash, args.verbose
    )

    # Collect decrypted masterkeys
    masterkeys = []
    for guid, key in decrypted:
        if key not in masterkeys:
            masterkeys.append(key)

        if guid == local_state_blob.mkguid and args.verbose:
            print(colored(f'    [+] Found matching UserMasterkey: "{local_state_blob.mkguid}"', ))
            print(colored(f'    [+] This UserMasterkey contains following key (hex): \n{hexdump(key)}', ))

    if not masterkeys:
        sys.exit(colored('[-] Failed to decrypt any masterkeys. Check credentials.', 'red'))

    print(colored(f'    [+] Successfully decrypted UserMasterkey', 'green'))

    # ========================================================================
    # PHASE 4: Decrypt Browser Master Encryption Key
    # ========================================================================
    bme_key = decrypt_browser_master_encryption_key(local_state_blob, masterkeys, args.verbose)

    if not bme_key:
        sys.exit(colored('[-] Failed to decrypt Browser Master Encryption key', 'red'))

    print(colored(f'    [+] Successfully extracted BME-key', 'green'))

    # ========================================================================
    # PHASE 5: Decrypt App-Bound Encryption Key (if applicable)
    # ========================================================================
    abe_key = None

    if check_abe_requirements(args, abe_system_blob):

        abe_key = decrypt_app_bound_encryption_key(
            abe_system_blob,
            args.system,
            args.security,
            args.systemmasterkey,
            masterkeys,
            args,
            args.verbose
        )

        if abe_key:
            print(colored(f'               [+] Successfully extracted App_Bound_Encryption-key', 'green'))
        else:
            print(colored('    [!] Failed to decrypt App_Bound_Encryption-key', 'red'))

    # ========================================================================
    # PHASE 6: Decrypt and Export Credentials
    # ========================================================================
    total_decrypted = 0

    if logins:
        total_decrypted += decrypt_and_display_logins(
            logins, bme_key, abe_key, masterkeys, args.export, args.verbose
        )

    if notes:
        total_decrypted += decrypt_and_display_notes(
            notes, bme_key, abe_key, masterkeys, args.export, args.verbose
        )

    # ========================================================================
    # PHASE 7: Bonus Features
    # ========================================================================
    parse_deleted_logins(args.loginfile)


if __name__ == '__main__':
    main()
