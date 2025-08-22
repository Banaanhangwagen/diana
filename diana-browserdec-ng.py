#!/usr/bin/python3
# -*- coding: utf-8 -*-
r'''
Copyright 2025, Tijl "Photubias" Deneut <@tijldeneut>
Copyright 2025, Banaanhangwagen <@banaanhangwagen>
This script provides offline decryption of Chromium based browser user data: Google Chrome, Edge Chromium and Opera

Update 2025-05: clean-up code
Update 2025-06: make it compatible with AppBoundEncryption
Update 2025-08: code clean-up and minor updates
'''

import argparse
import os
import json
import base64
import sqlite3
import re
import sys
import warnings

from Crypto.Cipher import AES, ChaCha20_Poly1305
from termcolor import colored

DPAPI_PREFIX = b'\x01\x00\x00\x00'
APPBOUND_PREFIX = b'\x76\x32\x30'

# Static keys for third stage app_bound_encryption-key derivation - see https://github.com/runassu/chrome_v20_decryption
aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

warnings.filterwarnings("ignore")

try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    sys.exit(colored("[-] Critical Error: The 'dpapick3' library is missing. "
                     "Please install it via `pip install dpapick3`", "red"))


def parse_local_state(local_state_file, verbose=True):
    oABESystemBlob = None
    Version = None
    try:
        with open(local_state_file, "r") as file:
            local_state = json.load(file)

            os_crypt = local_state.get("os_crypt", {})
            encrypted_key_b64 = os_crypt.get("encrypted_key")

            if not encrypted_key_b64:
                sys.exit(colored(f"[-] Error: 'os_crypt.encrypted_key' not found in \"{local_state_file}\".", "red"))

            encrypted_key = base64.b64decode(encrypted_key_b64)[5:]     # The first 5 bytes "DPAPI" are removed to get the actual DPAPI-blob
            local_state_blob = blob.DPAPIBlob(encrypted_key)

            if 'app_bound_encrypted_key' in os_crypt:
                bABESystemData = base64.b64decode(os_crypt['app_bound_encrypted_key']).strip(b'\x00')
                if bABESystemData.startswith(b'APPB'):                  # Check for custom 'APPB'-prefix before the actual DPAPI blob
                    oABESystemBlob = blob.DPAPIBlob(bABESystemData[4:])
                    print(colored(f"[INFO] Parsing Local State.", "yellow"))
                    if verbose:
                        print(f"    [+] Found encrypted_key: {encrypted_key[:32].hex():>97}...")
                        print(f"    [+] encrypted_key uses User-masterkey-GUID: {local_state_blob.mkguid:>50}")
                        print(f"    [+] Found app_bound_encrypted_key: {bABESystemData[:32].hex():>87}...")
                        print(f"    [+] app_bound_encrypted_key uses System-masterkey-GUID: {oABESystemBlob.mkguid:>32}")

            if 'variations_permanent_consistency_country' in local_state:
                Version = local_state['variations_permanent_consistency_country'][0]
                if Version: print(f'    [+] Detected Browser version: {Version:>42}')

        return local_state_blob, oABESystemBlob, Version
    except Exception as e:
        sys.exit(colored(f"[-] Error reading or processing \"Local State\"-file '{local_state_file}': {e}", 'red'))


def parse_login_file(filepath, guid_list):
    print(colored(f"[INFO] Parsing Login Data.", "yellow"))
    logins = []
    try:
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value, id FROM logins')
            rows = cursor.fetchall()
            if not rows:
                print(colored("[INFO] No credentials found in Login Data.", "yellow"))
        for url, user, pwd_blob, login_id in rows:
            if pwd_blob and pwd_blob.startswith(DPAPI_PREFIX):  # Check if password blob exists and is DPAPI encrypted
                parsed_blob = blob.DPAPIBlob(pwd_blob)
                if parsed_blob.mkguid not in guid_list:
                    guid_list.append(parsed_blob.mkguid)
            logins.append((url, user, pwd_blob, login_id))

    except sqlite3.Error as e:
        sys.exit(colored(f"[-] Error reading \"Login Data\"-file: {e}", 'red'))
    return logins, guid_list


def parse_notes(filepath, guid_list):
    notes = []
    try:
        with sqlite3.connect(filepath) as conn:
            conn.text_factory = bytes
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM password_notes')
            for note_blob, in cursor.fetchall():
                if note_blob and note_blob.startswith(DPAPI_PREFIX):
                    parsed_blob = blob.DPAPIBlob(note_blob)
                    if parsed_blob.mkguid not in guid_list:
                        guid_list.append(parsed_blob.mkguid)
                notes.append(note_blob)
    except sqlite3.Error as e:
        sys.exit(colored(f"[-] Error reading notes: {e}", 'red'))
    return notes, guid_list


def decrypt_bme(parsed_blob, masterkey):
    try:
        if parsed_blob.decrypt(masterkey):
            return parsed_blob.cleartext
    except Exception as e:
        print(colored(f"[-] Failed to decrypt blob with masterkey: {e}", "red"))
    return None


def decryptChromeString(encrypted_data, bme_key, abe_key=None, masterkeys=None, verbose=False):
    if not encrypted_data:
        return None

    # Case 1: DPAPI Encrypted (typically older items)
    if encrypted_data[:4] == DPAPI_PREFIX:
        if masterkeys:
            for bMK in masterkeys:
                dpapi_blob = blob.DPAPIBlob(encrypted_data)
                dpapi_blob.decrypt(bMK)
                if dpapi_blob.decrypted:
                    return dpapi_blob.cleartext.decode(errors='ignore')
        return None

    # Case 2: AppBound Encryption (v20 prefix)
    elif encrypted_data[:3] == APPBOUND_PREFIX:
        if abe_key:         # Structure: version (3 bytes)| IV (12 bytes) | ciphertext (var) | tag (16 bytes)
            iv = encrypted_data[3:15]
            payload = encrypted_data[15:-16]
            tag = encrypted_data[-16:]
            cipher = AES.new(abe_key, AES.MODE_GCM, iv)
            try:
                decrypted_payload = cipher.decrypt_and_verify(payload, tag)
                return decrypted_payload.decode(errors='ignore')
            except ValueError as e:
                if verbose:
                    print(colored(f"[-] Error decrypting Chrome password (v20): {', '.join(e.args) if e.args else e}", 'red'))
        return ""

    # Case 3: Chrome >= v80 non-DPAPI (uses key derived from Local State)
    # Typically starts with "v10"
    elif encrypted_data.startswith(b'v10'):
        try:
            iv = encrypted_data[3:15]
            payload = encrypted_data[15:]
            cipher = AES.new(bme_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)
            return decrypted[:-16].decode(errors='ignore')
        except Exception:
            if verbose:
                print(colored("[-] Error decrypting, maybe Browser Engine < v80", 'red'))
            pass
    return None


def decryptLogins(items, bme_key, abe_key=None, masterkeys=None, csvfile=None, verbose=False, label='Credential'):
    count = 0

    if csvfile:
        file_path = f'{label.lower()}_{csvfile}'
        with open(file_path, 'a') as f:
            if label == 'Credential':
                f.write("ID;Version;URL;Username;Password\n")

            for item in items:
                encrypted_data = decryptChromeString(item[2], bme_key, abe_key, masterkeys, verbose)

                print('ID:        {}'.format(item[3]))
                print('Version:   {}'.format(item[2][:3].decode('ascii')))
                print('URL:       {}'.format(item[0]))
                print('User Name: {}'.format(item[1]))
                print('Password:  {}'.format(encrypted_data))
                print('*' * 50)

                if encrypted_data is not None:
                    count += 1

                if label == 'Credential':
                    f.write(f"{item[3]};{item[2][:3].decode('ascii')};{item[0]};{item[1]};{encrypted_data}\n")
                else:
                    f.write('Note\n')
    else:
        for item in items:
            encrypted_data = decryptChromeString(item[2], bme_key, abe_key, masterkeys, verbose)

            print('ID:        {}'.format(item[3]))
            print('Version:   {}'.format(item[2][:3].decode('ascii')))
            print('URL:       {}'.format(item[0]))
            print('User Name: {}'.format(item[1]))
            print('Password:  {}'.format(encrypted_data))
            print('*' * 50)
            if encrypted_data is not None:
                count += 1
    return count


def decryptNotes(notes, bme_key, abe_key=None, masterkeys=None, guid_list=None, csvfile=None, verbose=False):
    count = 0
    if csvfile:
        with open('notes_' + csvfile, 'a') as f:
            f.write('Note\n')

    for note in notes:
        note_decrypted = decryptChromeString(note, bme_key, abe_key, masterkeys, verbose)
        if verbose:
            print('Note:  {}'.format(note_decrypted))
            print('*' * 50)
        if note_decrypted is not None:
            count += 1
        if csvfile:
            with open('notes_' + csvfile, 'a') as f:
                f.write('{}\n'.format(note_decrypted))
    return count


def load_masterkeys_from_file(filepath):
    with open(filepath) as f:
        return [bytes.fromhex(line.strip()) for line in f if len(line.strip()) in (40, 128)]


def process_system_registry(args, abe_system_blob):
    abe_user_blob = None

    try:
        if args.verbose:
            print(f'    [+] Found SYSTEM & SECURITY, trying first-stage app_bound_encrypted_key decryption using SYSTEM')

        oReg = registry.Regedit()
        oSecrets = oReg.get_lsa_secrets(args.security, args.system)
        bDPAPI_SYSTEM = oSecrets.get('DPAPI_SYSTEM')['CurrVal']

        if not bDPAPI_SYSTEM:
            print(colored(f"[-] Failed to extract DPAPI_SYSTEM key.","red"))
            return None

        else:
            if args.verbose:
                print(f"        [+] Successfully extracted DPAPI_SYSTEM key from registry: {bDPAPI_SYSTEM.hex()}")

        oMKP1 = masterkey.MasterKeyPool()
        oMKP1.loadDirectory(args.systemmasterkey)
        oMKP1.addSystemCredential(bDPAPI_SYSTEM)

        if oMKP1.try_credential_hash(None, None) > 0:  # Decrypt system MKs
            if args.verbose:
                print(f'    [+] Loaded {len(oMKP1.keys)} potential system masterkey(s) from SystemMasterKey-folder')
            for lstMKL_system in oMKP1.keys.values():
                for oMK_system in lstMKL_system:
                    if oMK_system.decrypted:
                        system_mk_bytes = oMK_system.get_key()

                        # Now, try to decrypt the abe_system_blob with this system_mk
                        if args.verbose:
                            print(colored(f"            [*] Trying system masterkey \"{oMK_system.guid.decode()}\" to decrypt app_bound_encrypted_key","magenta"))

                        bABEUserData_payload = decrypt_bme(abe_system_blob, system_mk_bytes)
                        if bABEUserData_payload:
                            abe_user_blob = blob.DPAPIBlob(bABEUserData_payload)  # This is the second-stage blob
                            if args.verbose:
                                print(colored(f"    [+] Successfully decrypted app_bound_encrypted_key using System Masterkey \"{oMK_system.guid.decode()}\"."))
                                print(colored(f"    [+] This second app_bound_encrypted_key now requires User Masterkey \"{abe_user_blob.mkguid}\" for third-stage app_bound_encrypted_key."))
                            return abe_user_blob
            if not abe_user_blob:
                print(colored("    [-] Failed to decrypt any System Masterkeys using DPAPI_SYSTEM LSA key.", "red"))

        if not abe_user_blob and args.verbose:
            print(colored("    [-] Could not decrypt app_bound_encrypted_key. Did you point to the correct System Masterkey-folder?","red"))

    except Exception as e:
        print(colored(f"    [-] Error during app_bound_encrypted_key decryption: {e}", "red"))

    return abe_user_blob


def decrypt_with_static_keys(abe_key, verbose=False):
    if abe_key[0:5] == b'\x1f\x00\x00\x00\x02' and b"Chrome" in abe_key:
        if verbose:
            print(f'    [+] Trying to decrypt app_bound_encrypted_key with known static keys')

        bFlag = abe_key[-61:-60]
        iv = abe_key[-60:-48]
        bCiphertext = abe_key[-48:-16]
        tag = abe_key[-16:]

        if bFlag == b'\x01':
            if verbose:
                print(f'       [!] Found flag "{bFlag.hex()}". Using AES-GCM with static key...')
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        elif bFlag == b'\x02':
            if verbose:
                print(f'        [!] Found flag "{bFlag.hex()}". Using ChaCha20-Poly1305 with static key...')
            cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
        else:
            print(colored(f'Unknown flag "{bFlag.hex()}"', 'red'))
            return abe_key[-32:]

        try:
            return cipher.decrypt_and_verify(bCiphertext, tag)
        except ValueError:
            pass

    return abe_key[-32:]


def process_masterkeys(args, local_state_blob, abe_system_blob=None):
    masterkeys = []
    masterkey_blob = None
    abe_masterkey = None
    mkp = None

    # Option 1: Direct masterkey
    if args.masterkey:
        print(f'[!] Trying direct masterkey from -k argument.')
        masterkey_blob = bytes.fromhex(args.masterkey)

    # Option 1b: List of masterkeys
    elif args.masterkeylist:
        print(f'[!] Trying list of masterkeys from file: {args.masterkeylist}')
        masterkeys = load_masterkeys_from_file(args.masterkeylist)

    # Prepare MasterKeyPool if mkfile is provided (for user or system keys)
    if args.mkfile:
        mkp = masterkey.MasterKeyPool()
        if os.path.isfile(args.mkfile):
            mkp.addMasterKey(open(args.mkfile, 'rb').read())
        else:
            mkp.loadDirectory(args.mkfile)
            if args.verbose:
                print(f'    [+] Loaded {len(mkp.keys)} potential user-masterkey(s) from UserMasterKey-folder')

    abe_user_blob = None
    if args.system and args.security and args.systemmasterkey and abe_system_blob:
        abe_user_blob = process_system_registry(args, abe_system_blob)

    # Option 2: PVK domain key
    if mkp and args.pvk:
        print(f'[!] Trying MasterKey decryption with the PVK domain key')
        if mkp.try_domain(args.pvk) > 0:
            for mk_guid in list(mkp.keys):
                mk = mkp.getMasterKeys(mk_guid)[0]
                if mk.decrypted:
                    if mk.get_key() not in masterkeys:
                        masterkeys.append(mk.get_key())
                    if mk_guid.decode(errors='ignore') == local_state_blob.mkguid:
                        masterkey_blob = mk.get_key()
                        print(colored('[+] Success, user Masterkey decrypted: ' + masterkey_blob.hex(), 'green'))
                    if abe_user_blob and mk_guid.decode(errors='ignore') == abe_user_blob.mkguid:
                        abe_masterkey = mk.get_key()
                        print(colored(f'[+] Success, app_bound_encrypted_key decrypted: {abe_masterkey.hex()}', 'green'))

    # Option 3: User SID + password
    if args.mkfile and args.sid and (args.password or args.pwdhash):
        if args.verbose:
            print(f'    [+] Trying decryption of User Masterkey with user-SID and provided password...')

        if args.password:
            mkp.try_credential(args.sid, args.password)
        else:
            mkp.try_credential_hash(args.sid, args.pwdhash)

        for mk_guid in list(mkp.keys):
            mk = mkp.getMasterKeys(mk_guid)[0]
            if mk.decrypted:
                if mk.get_key() not in masterkeys:
                    masterkeys.append(mk.get_key())
                if mk_guid.decode(errors='ignore') == local_state_blob.mkguid:
                    masterkey_blob = mk.get_key()
                    if args.verbose:
                        print(colored(f'        [+] Successfully decrypted the User Masterkey'))
                    # print(colored(f'            [+] {masterkey_blob.hex()}', 'cyan'))

    return masterkey_blob, masterkeys, mkp, abe_masterkey, abe_user_blob


def validate_paths(args):
    checks = [
        (args.statefile, 'Local State file', os.path.isfile),
        (args.loginfile, 'Login Data file', os.path.isfile),
        (args.masterkeylist, 'Masterkey list file', os.path.isfile),
        (args.system, 'SYSTEM hive file', os.path.isfile),
        (args.security, 'SECURITY hive file', os.path.isfile),
        (args.pvk, 'PVK file', os.path.isfile),
        (args.systemmasterkey, 'System Masterkey folder', os.path.isdir),
        (args.mkfile, 'User Masterkey folder', os.path.isdir),
    ]

    for path, desc, check_func in checks:
        if path and not check_func(path):
            sys.exit(colored(f"[-] Error: {desc} not found: {path}", "red"))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extract and decrypt Chromium-based browser credentials")

    parser.add_argument('-t', '--statefile', metavar="", default='Local State', help='Path to "Local State" file')
    parser.add_argument('-l', '--loginfile', metavar="", help='Path to "Login Data" SQLite DB')
    # parser.add_argument('-c', '--cookies', metavar="", help='Path to Cookies file (optional)')
    parser.add_argument('-k', '--masterkey', metavar="", help='Direct Masterkey (128 hex chars or SHA1)')
    parser.add_argument('-f', '--masterkeylist', metavar="", help='File containing Masterkeys')
    parser.add_argument('-m', '--mkfile', metavar="",
                        default=os.path.join('%AppData%', 'Microsoft', 'Protect', 'S-1-5-21-...'),
                        help='User Masterkey folder')
    parser.add_argument('-s', '--sid', metavar="", help='User SID')
    parser.add_argument('-a', '--pwdhash', metavar="", help='SHA1 password hash')
    parser.add_argument('-p', '--password', metavar="", help='User password')
    parser.add_argument('-r', '--pvk', metavar="", help='Domain PVK file')
    parser.add_argument('-o', '--export', metavar="", help='Export decrypted values to CSV')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose output')
    parser.add_argument('-y', '--systemmasterkey', metavar="",
                        default=os.path.join('%Windows%', 'System32', 'Microsoft', 'Protect', 'S-1-5-18', 'User'),
                        help='System Masterkey folder')
    parser.add_argument('-e', '--system', metavar="", default=os.path.join('Windows', 'System32', 'config', 'SYSTEM'),
                        help='SYSTEM Registry hive')
    parser.add_argument('-u', '--security', metavar="",
                        default=os.path.join('Windows', 'System32', 'config', 'SECURITY'),
                        help='SECURITY Registry hive')

    args = parser.parse_args()

    if args.verbose:
        print(colored('[INFO] Welcome. To decrypt, one of the four following combinations is required:', 'yellow'))
        print(f"{' (1)':<4} {'Masterkey-file, SID and User-Pwd (or Hash)':<50}")
        print(f"{' (2)':<4} {'Decrypted Masterkey':<50}")
        print(f"{' (3)':<4} {'File containing decrypted Masterkeys':<50}")
        print(f"{' (4)':<4} {'Masterkey-file and Domain PVK':<50}")

        print(colored("[INFO] Needed files can be found here:", 'yellow'))
        print(f"{' Local State:':<14} {'%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Local State':<60}")
        print(f"{' Passwords:':<14} {'%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Default\\Login Data':<60}")
        print(f"{' Cookies:':<14} {'%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Default\\Network\\Cookies':<60}")
        print(f"{' Masterkey(s):':<14} {'%appdata%\\Microsoft\\Protect\\S-1-5-21...-folder':<60}")

    validate_paths(args)

    if args.mkfile:
        args.mkfile = args.mkfile.replace('*', '')
        if not os.path.exists(args.mkfile):
            sys.exit(colored(f"[-] Error: mkfile not found: {args.mkfile}", "red"))

        if not args.sid:
            match = re.search(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", args.mkfile)
            if match:
                args.sid = match.group()
                print(colored(f"[INFO] Detected user with SID: {args.sid}", 'yellow'))

    if args.mkfile and args.sid and not args.password and not args.pwdhash:
        args.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        # On older systems: args.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0'
        print(colored('[+] No password provided, using empty hash', 'green'))

    if args.pwdhash:
        try:
            args.pwdhash = bytes.fromhex(args.pwdhash)
        except ValueError:
            sys.exit(colored(f"[-] Error: Invalid hex string for password hash (pwdhash): {args.pwdhash}", "red"))


    guid_list, items, masterkeys = [], [], []
    bme_key = None
    abe_key = None

    ## Parse Local State file
    local_state_blob, abe_system_blob, Version = parse_local_state(args.statefile, args.verbose)
    guid_list.append(local_state_blob.mkguid)

    ## Get Logins and Notes, if any
    if args.loginfile:
        items, guid_list = parse_login_file(args.loginfile, guid_list)
        print(f'    [+] Found {len(items)} credential(s) in "Login Data".')
        notes, guid_list = parse_notes(args.loginfile, guid_list)
        print(f'    [+] Found {len(notes)} note(s) in "Login Data".')
    else:
        sys.exit(colored('[-] Error: No \"Login Data\"-file provided. Exiting...', 'red'))

    ## If no decryption details are provided, feed results back
    if not args.masterkey and not args.masterkeylist and not args.mkfile:
        if len(guid_list) > 1:
            # guid_list.sort()
            print(f'[!] Found {len(guid_list)} different Masterkeys, required for decrypting all logins and/or cookies:')
            for sGUID in guid_list:
                print('    ' + sGUID)
        print(colored('[!] Input the masterkey-files and accompanying decryption details to continue decrypting','yellow'))
        exit(0)

    print(colored('[INFO] Extracting Browser Master Encryption and App-Bound Encryption key from \"Local State\"', 'yellow'))

    # Process masterkeys based on provided arguments
    masterkey_blob, masterkeys_list, mkp, abe_masterkey, abe_user_blob = process_masterkeys(args, local_state_blob, abe_system_blob)
    masterkeys = masterkeys_list

    # Try to get Browser Master Encryption key
    for mk in masterkeys:
        bme_key = decrypt_bme(local_state_blob, mk)
        if bme_key:
            break

    if not bme_key and masterkey_blob:
        bme_key = decrypt_bme(local_state_blob, masterkey_blob)
        if masterkey_blob and masterkey_blob not in masterkeys:
            masterkeys.append(masterkey_blob)

    if bme_key:
        print(colored(f'    [+] Successfully got Browser Master Encryption key: {bme_key.hex()}'))
    else:
        print(
            colored(f'[-] Error decrypting Browser Master Encryption key. Is the (correct) password provided?', 'red'))
        exit(0)

    # ABE key handling
    if abe_user_blob:
        for mk in masterkeys:
            abe_key = decrypt_bme(abe_user_blob, mk)
            if abe_key:
                break

        if not abe_key and abe_masterkey:
            abe_key = decrypt_bme(abe_user_blob, abe_masterkey)

        if abe_key:
            abe_key = decrypt_with_static_keys(abe_key, args.verbose)
            print(colored(f'    [+] Success! Final app_bound_encrypted_key: {abe_key.hex()}', 'green'))

    ## Decrypt
    if args.loginfile:
        print(colored('[INFO] Decrypting logins from \"Login Data\"....', 'yellow'))
        decrypted = decryptLogins(items, bme_key, abe_key, masterkeys, args.export, args.verbose, 'Credential')
        print(colored(f'[INFO] Decrypted {decrypted} out of {len(items)} credentials', 'yellow'))

        ## Decrypting Notes
        print(colored('[INFO] Decrypting notes....', 'yellow'))
        print('*' * 50)
        if bme_key and notes:
            count = decryptNotes(notes, bme_key, abe_key, masterkeys, guid_list, args.export, args.verbose)
            print(f'[!] Decrypted {count}/{len(notes)} notes\n')

    ## Display deleted logins as bonus
    if args.loginfile:
        database = sqlite3.connect(args.loginfile)
        with database:
            for values in database.execute('SELECT origin_domain, username_value FROM stats'):
                print(colored("[BONUS-DELETED LOGIN]: ", 'yellow'))
                print(values[0], "\t", values[1])
