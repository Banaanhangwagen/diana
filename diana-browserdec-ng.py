#!/usr/bin/python3
# -*- coding: utf-8 -*-
r'''
Copyright 2025, Tijl "Photubias" Deneut <@tijldeneut>
Copyright 2025, Banaanhangwagen <@banaanhangwagen>
This script provides offline decryption of Chromium based browser user data: Google Chrome, Edge Chromium and Opera

Update 2025-05: clean-up code
Update 2025-06: make it compatible with AppBoundEncryption
Update 2025-08: code clean-up and minor updates
Update 2025-11: code refactoring and adding flag "v3"
'''

import argparse
import os
import json
import base64
import sqlite3
import re
import sys
import warnings
import struct

from Crypto.Cipher import AES, ChaCha20_Poly1305
from termcolor import colored

warnings.filterwarnings("ignore")

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
DPAPI_PREFIX_LENGTH = 5             # Length of "DPAPI" text prefix in base64
APPBOUND_PREFIX = b'\x76\x32\x30'   # "v20"
APPB_PREFIX_LENGTH = 4              # Length of "APPB" prefix
V10_PREFIX = b'v10'

# Static keys for third-stage app_bound_encryption-key derivation -
# see: https://github.com/tijldeneut/diana/pull/6
AES_STATIC_KEY = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
CHACHA20_STATIC_KEY = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

# Default empty password SHA1 hash
EMPTY_PASSWORD_HASH = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

# Encryption flags
FLAG_AES_GCM = b'\x01'
FLAG_CHACHA20 = b'\x02'


# ============================================================================
# FILE PARSING
# ============================================================================
def parse_local_state(filepath, verbose=True):
    """Extract encrypted_key/app_bound_encrypted_key and browser version from Local State file."""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        os_crypt = data.get("os_crypt", {})

        # Extract and decode encrypted_key
        encrypted_key_b64 = os_crypt.get("encrypted_key")
        if not encrypted_key_b64:
            sys.exit(colored(f"[-] Error: 'encrypted_key' not found in {filepath}", "red"))

        encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Skip "DPAPI" prefix
        local_state_blob = blob.DPAPIBlob(encrypted_key)

        # Extract and decode app_bound_encrypted_key if present
        app_bound_encrypted_key_b64 = os_crypt.get("app_bound_encrypted_key")
        if not app_bound_encrypted_key_b64:
            if verbose:
                print(colored(f"[-] Error: 'encrypted_key' not found in {filepath}", "red"))
            abe_system_blob = None
        else:
            app_bound_encrypted_key = base64.b64decode(app_bound_encrypted_key_b64).strip(b'\x00')
            abe_system_blob = blob.DPAPIBlob(app_bound_encrypted_key[APPB_PREFIX_LENGTH:])

        if verbose:
            print(colored("[INFO] Parsing Local State", "yellow"))
            print(f"    [+] GUID encrypted_key :           {local_state_blob.mkguid}")
            if abe_system_blob:
                print(f"    [+] GUID app_bound_encrypted_key : {abe_system_blob.mkguid}")

        # Extract browser version
        version = None
        if 'variations_permanent_consistency_country' in data:
            version = data['variations_permanent_consistency_country'][0]
            if version and verbose:
                print(f"    [+] Browser version:               {version}")

        return local_state_blob, abe_system_blob, version

    except Exception as e:
        sys.exit(colored(f"[-] Error reading Local State file: {e}", 'red'))


def parse_login_data(filepath, guid_list):
    """Extract login credentials from Login Data SQLite database."""
    print(colored("[INFO] Parsing Login Data", "yellow"))
    logins = []

    try:
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value, id FROM logins')
            rows = cursor.fetchall()

            if not rows:
                print(colored("[INFO] No credentials found", "yellow"))
                return logins, guid_list

        for url, username, pwd_blob, login_id in rows:
            if pwd_blob and pwd_blob.startswith(DPAPI_PREFIX):
                parsed_blob = blob.DPAPIBlob(pwd_blob)
                if parsed_blob.mkguid not in guid_list:
                    guid_list.append(parsed_blob.mkguid)
            logins.append((url, username, pwd_blob, login_id))

        print(f"    [+] Found {len(logins)} credential(s)")

    except sqlite3.Error as e:
        sys.exit(colored(f"[-] Error reading Login Data: {e}", 'red'))

    return logins, guid_list


def parse_notes(filepath, guid_list):
    """Extract password notes from Login Data database."""
    notes = []

    try:
        with sqlite3.connect(filepath) as conn:
            conn.text_factory = bytes
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM password_notes')

            for (note_blob,) in cursor.fetchall():
                if note_blob and note_blob.startswith(DPAPI_PREFIX):
                    parsed_blob = blob.DPAPIBlob(note_blob)
                    if parsed_blob.mkguid not in guid_list:
                        guid_list.append(parsed_blob.mkguid)
                notes.append(note_blob)

        print(f"    [+] Found {len(notes)} note(s)")

    except sqlite3.Error as e:
        print(colored(f"[-] Error reading notes: {e}", 'red'))

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
        pass  # Stats table may not exist


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
            print(f"    [+] Stage 0 - Extracted DPAPI_SYSTEM key from registry: {dpapi_system.hex()[:16]}...")

        return dpapi_system

    except Exception as e:
        print(colored(f"[-] Stage 0 - Error extracting DPAPI_SYSTEM: {e}", "red"))
        return None


def load_user_masterkeys(mkfile_path, sid=None, password=None, pwdhash=None, verbose=False):
    """Load and decrypt UserMasterkeys using provided credentials."""
    mkp = masterkey.MasterKeyPool()

    # Load masterkey files
    if os.path.isfile(mkfile_path):
        mkp.addMasterKey(open(mkfile_path, 'rb').read())
    else:
        mkp.loadDirectory(mkfile_path)
        if verbose:
            print(f'    [+] Loaded {len(mkp.keys)} UserMasterkey file(s)')

    decrypted_keys = []

    # Decrypt with user credentials
    if sid and (password or pwdhash):
        if verbose:
            print('    [+] Trying provided password on each UserMasterkey')
        if password:
            mkp.try_credential(sid, password)
        else:
            mkp.try_credential_hash(sid, pwdhash)

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
        if verbose:
            print(f'    [+] Stage 1 - Loaded {len(mkp.keys)} SystemMasterkey(s)')

        for mk_list in mkp.keys.values():
            for mk in mk_list:
                if mk.decrypted:
                    system_mk = mk.get_key()
                    system_masterkeys.append((mk.guid.decode(), system_mk))

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

    if encrypted_data[:4] == DPAPI_PREFIX:
        return 'DPAPI'
    elif encrypted_data[:3] == APPBOUND_PREFIX:
        return 'APPBOUND'
    elif encrypted_data.startswith(V10_PREFIX):
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


def decrypt_dpapi_password(encrypted_data, masterkeys, verbose=False):
    """Decrypt DPAPI-encrypted password (older items)."""
    if not masterkeys:
        return None

    for mk in masterkeys:
        dpapi_blob = blob.DPAPIBlob(encrypted_data)
        dpapi_blob.decrypt(mk)
        if dpapi_blob.decrypted:
            return dpapi_blob.cleartext.decode(errors='ignore')
    return None


def decrypt_appbound_password(encrypted_data, abe_key, verbose=False):
    """Decrypt App-Bound encrypted password (v20 prefix)."""
    if not abe_key:
        return None

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
        return None


def decrypt_v10_password(encrypted_data, bme_key, verbose=False):
    """Decrypt Chrome v80+ password (v10 prefix)."""
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


def decrypt_chrome_password(encrypted_data, bme_key, abe_key=None, masterkeys=None, verbose=False):
    """
    Main password decryption dispatcher based on encryption type.
    """
    enc_type = detect_encryption_type(encrypted_data)

    if enc_type == 'DPAPI':
        return decrypt_dpapi_password(encrypted_data, masterkeys, verbose)
    elif enc_type == 'APPBOUND':
        return decrypt_appbound_password(encrypted_data, abe_key, verbose)
    elif enc_type == 'V10':
        return decrypt_v10_password(encrypted_data, bme_key, verbose)

    return None


def decrypt_browser_master_encryption_key(local_state_blob, masterkeys, verbose=False):
    """
    Decrypt the Browser Master Encryption (BME) key from Local State.
    """
    print(colored('\n[INFO] Extracting Browser_Master_Encryption-key from local_state_blob...', 'yellow'))

    for mk in masterkeys:
        bme_key = decrypt_dpapi_blob(local_state_blob, mk)
        if bme_key:
            if verbose:
                print(colored(f'    [+] BME_key (hex): {bme_key.hex()[:16]}...', ))
            return bme_key

    return None


def decrypt_abe_stage1_with_system_key(abe_system_blob, system_masterkeys, verbose=False):
    """
    Stage 1: Decrypt app_bound_encrypted_key using system masterkeys.
    """
    if verbose:
        print('    [+] Stage 1 - Decrypting app_bound_encrypted_key with SystemMasterkey')

    for guid, system_mk in system_masterkeys:
        if verbose:
            print(colored(f"         [*] Trying SystemMasterkey: {guid}", "magenta"))

        decrypted = decrypt_dpapi_blob(abe_system_blob, system_mk)

        if decrypted:
            abe_user_blob = blob.DPAPIBlob(decrypted)
            if verbose:
                print(colored(f"         [+] Success! SystemMasterkey {guid} decrypted the blob", ))
                # print(colored(f"    [DBG] abe_user_blob (object): {abe_user_blob}", "cyan"))
                print(colored(f"         [+] Parsing blob. Now we need second UserMasterkey: {abe_user_blob.mkguid}", ))
            return abe_user_blob

    if verbose:
        print(colored("    [-] Failed to decrypt with system masterkeys", "red"))
    return None


def decrypt_abe_stage2_with_user_key(abe_user_blob, masterkeys, verbose=False):
    """
    Stage 2: Decrypt abe_user_blob using new UserMasterkey.
    """
    if verbose:
        print(colored(f'    [+] Stage 2 - Decrypting abe_user_blob with new UserMasterkey', ))

    for mk in masterkeys:
        abe_encrypted_key = decrypt_dpapi_blob(abe_user_blob, mk)
        if abe_encrypted_key:
            if verbose:
                print(colored(f'    [+] Stage 2 - Success! Got encrypted_ABE-key: {abe_encrypted_key.hex()}', ))
            return abe_encrypted_key

    if verbose:
        print(colored("    [-] Stage 2 - Failed to decrypt with user masterkeys", "red"))
    return None


def decrypt_abe_stage3_with_static_keys(abe_encrypted_key, verbose=False):
    """
    Stage 3: Decrypt app_bound_encrypted_key using known static keys.
    """
    # Parse the ABE blob structure
    try:
        header_len = struct.unpack('<I', abe_encrypted_key[:4])[0]
        header = abe_encrypted_key[4:4 + header_len].strip(b'\x02').decode(errors='ignore')

        if verbose:
            print(colored(f'    [+] Stage 3 - Found header: "{header}"', ))

        content_len = struct.unpack('<I', abe_encrypted_key[4 + header_len:4 + header_len + 4])[0]
        content = abe_encrypted_key[8 + header_len:8 + header_len + content_len]

        # Handle unversioned format (some Edge versions)
        if content_len == 32:
            if verbose:
                print(colored('    [+] Stage 3 - Version flag not found, using raw key', ))
            return content

        # Parse versioned format
        version = int(content[0])
        content = content[1:]

        if verbose:
            print(colored(f'    [+] Stage 3 - Detected ABE_key version: {version}', ))

        if version <= 2:
            # Version 1 or 2: Version|IV|ciphertext|tag (1|12|32|16 bytes)
            iv = content[:12]
            ciphertext = content[12:12 + 32]
            tag = content[12 + 32:12 + 32 + 16]

            # Select cipher based on version
            if version == 1:
                if verbose:
                    print('        [+] Using AES-GCM (version 1)')
                cipher = AES.new(AES_STATIC_KEY, AES.MODE_GCM, nonce=iv)
            elif version == 2:
                if verbose:
                    print('        [+] Using ChaCha20-Poly1305 (version 2)')
                cipher = ChaCha20_Poly1305.new(key=CHACHA20_STATIC_KEY, nonce=iv)

            decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
            if verbose:
                print(colored(f'    [+] Stage 3 - decrypted ABE_key: {decrypted_key.hex()}', ))
            return decrypted_key

        elif version == 3:
            # Version 3: Version|encAES|IV|ciphertext|tag (1|32|12|32|16 bytes)
            print(colored('    [-] Stage 3 - ABE_key version 3 detected but not yet implemented', 'red'))
            # print(colored('    [!] Using fallback: last 32 bytes as key', 'yellow'))
            return None
            # return abe_encrypted_key[-32:]
        else:
            print(colored(f'    [-] Stage 3 - Unknown ABE_key version: {version}', 'red'))
            return abe_encrypted_key[-32:]

    except Exception as e:
        if verbose:
            print(colored(f'    [-] Stage 3 - Error parsing ABE_key blob: {e}', 'red'))
            print(colored('    [!] Using fallback: last 32 bytes as key', 'yellow'))
        return abe_encrypted_key[-32:]



def decrypt_app_bound_encryption_key(abe_system_blob, system_hive, security_hive,
                                     system_mk_folder, user_masterkeys, verbose=False):
    """
    Complete 3-stage App-Bound Encryption key decryption process.
    """
    print(colored('\n[INFO] Processing App-Bound Encryption (3-stage decryption)...', 'yellow'))

    # Stage 0: Extract DPAPI_SYSTEM from registry
    dpapi_system = extract_dpapi_system_key(system_hive, security_hive, verbose)
    if not dpapi_system:
        return None

    # Load system masterkeys
    system_masterkeys = load_system_masterkeys(system_mk_folder, dpapi_system, verbose)
    if not system_masterkeys:
        print(colored("    [-] No system masterkeys available", "red"))
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
    abe_key = decrypt_abe_stage3_with_static_keys(abe_encrypted_key, verbose)

    return abe_key



# ============================================================================
# OUTPUT FUNCTIONS
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

    print(colored(f'[INFO] Decrypted {decrypted_count}/{len(notes)} notes', 'yellow'))
    return decrypted_count


# ============================================================================
# VALIDATION & SETUP
# ============================================================================
def validate_file_paths(args):
    """Validate that all provided file paths exist."""
    checks = [
        (args.statefile, 'Local State file', os.path.isfile),
        (args.loginfile, 'Login Data file', os.path.isfile),
        (args.system, 'SYSTEM hive', os.path.isfile),
        (args.security, 'SECURITY hive', os.path.isfile),
        (args.systemmasterkey, 'System Masterkey folder', os.path.isdir),
        (args.mkfile, 'User Masterkey folder', os.path.isdir),
    ]

    for path, desc, check_func in checks:
        if path and not check_func(path):
            sys.exit(colored(f"[-] Error: {desc} not found: {path}", "red"))


def parse_sid_from_masterkey_path(mkfile_path):
    """Extract user SID from UserMasterkey folder path."""
    match = re.search(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", mkfile_path)
    return match.group() if match else None


def display_usage_information():
    print(colored('[INFO] Welcome! To offline decrypt Chromium-passwords you need:', 'yellow'))
    print(f"  Local State, Login Data, UserMasterkeys folder + SID, SystemMasterkeys folder, SYSTEM, SECURITY and the user password/Cachedata-key")

    print(colored("[INFO] File locations:", 'yellow'))
    print(f"  Local State:      %appdata%\\Local\\{{Google/Microsoft}}\\{{Chrome/Edge}}\\User Data\\Local State")
    print(f"  Login Data:       %appdata%\\Local\\{{Google/Microsoft}}\\{{Chrome/Edge}}\\User Data\\Default\\Login Data")
    print(f"  UserMasterkeys:   %appdata%\\Roaming\\Microsoft\\Protect\\S-1-5-21...-folder")
    print(f"  SystemMasterkeys: %Windows%\\System32\\Microsoft\\Protect\\S-1-5-18\\User-folder")
    print(f"  Cachedata:        %Windows%\\System32\\config\\systemprofile\\AppData\\local\\microsoft\\windows\\CloudAPCache\\MicrosoftAccount\\Cachedata")


def setup_argument_parser():
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(description="Decrypt Chromium browser credentials offline")

    # Input files
    parser.add_argument('-t', '--statefile', metavar="", default='Local State',
                        help='Path to "Local State" file')
    parser.add_argument('-l', '--loginfile', metavar="",
                        help='Path to "Login Data" SQLite database')

    # Masterkey options
    parser.add_argument('-m', '--mkfile', metavar="", required=True,
                        help='UserMasterkey folder path')
    parser.add_argument('-y', '--systemmasterkey', metavar="",
                        help='SystemMasterkey folder path (required for v20+ ABE)')

    # User credentials
    parser.add_argument('-s', '--sid', metavar="",
                        help='User SID (auto-detected if not provided)')
    parser.add_argument('-p', '--password', metavar="",
                        help='User password')
    parser.add_argument('-a', '--pwdhash', metavar="",
                        help='SHA1 password hash (hex format)')

    # Registry options
    parser.add_argument('-e', '--system', metavar="",
                        help='SYSTEM registry hive (required for v20+ ABE)')
    parser.add_argument('-u', '--security', metavar="",
                        help='SECURITY registry hive (required for v20+ ABE)')

    # Output options
    parser.add_argument('-o', '--export', metavar="",
                        help='Export results to CSV file (provide base filename)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output with detailed information')

    return parser


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
    """Main program execution flow."""
    # ========================================================================
    # PHASE 1: Setup & Validation
    # ========================================================================
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Display usage info if verbose
    if args.verbose:
        display_usage_information()

    # Prepare and validate arguments
    args = prepare_arguments(args)
    validate_file_paths(args)

    # ========================================================================
    # PHASE 2: Parse Input Files
    # ========================================================================
    # Parse Local State for encryption keys
    local_state_blob, abe_system_blob, version = parse_local_state(
        args.statefile, args.verbose
    )
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
            print(colored(f'    [+] Found matching UserMasterkey "{local_state_blob.mkguid}"', ))
            print(colored(f'    [+] This UserMasterkey contains key (hex): {key.hex()[:16]}...', ))

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
            args.verbose
        )

        if abe_key:
            print(colored(f'    [+] Successfully extracted App_Bound_Encryption-key', ))
        else:
            print(colored('    [-] Failed to decrypt App_Bound_Encryption-key', 'yellow'))

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
