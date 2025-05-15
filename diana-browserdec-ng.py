#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
Copyright 2025, Tijl "Photubias" Deneut <@tijldeneut>
Copyright 2025, Banaanhangwagen <@banaanhangwagen>
This script provides offline decryption of Chromium based browser user data: Google Chrome, Edge Chromium and Opera

Credentials (and cookies) are encrypted using a Browser Master Encryption key.
This BME key is encrypted using DPAPI in the file "Local State", mostly located at
%localappdata%\{Google/Microsoft}\{Chrome/Edge}\User Data
or %appdata%\Opera Software\Opera Stable
This BME key can then be used to decrypt (AES GCM) the login data and cookies, mostly located at
%localappdata%\{Google/Microsoft}\{Chrome/Edge}\User Data\Default\
or %appdata%\Opera Software\Opera Stable\

DPAPI decrypting the BME key is the hard part. It uses the user DPAPI Masterkey secret from a DPAPI Masterkey file (MK file).
To identify which DPAPI Masterkey file, the browser "Local State" file contains the cleartext GUID, which is the filename of the MK file
Usually this DPAPI MK file is located at
%appdata%\Microsoft\Protect\<SID>\<GUID>
This DPAPI Masterkey secret is 64bytes in length and can be found either encrypted in lsass memory or encrypted inside the above MK file
The secret within the MK file can be decrypted either via Local AD Domain RSA Key or using local user details
- Local User Details are user SID + SHA1 password hash or sometimes user SID + NTLM password hash (on AzureAD only systems there are no local details and lsass is the only way for now)
- AD Domain RSA Key is the PVK export containing details to construct a private/public RSA encryption certificate, having this and the user MK file can decrypt all domain members

## Generating a list of decrypted MK's can be done with mkudec.py:
e.g. mkudec.py %appdata%\Roaming\Microsoft\Protect\<SID>\* -a <hash> | findstr Secret > masterkeylist.txt
#> and remove all strings '    Secret:'

Update 2025-05-15: clean-up code
'''
import argparse
import os
import json
import base64
import sqlite3
import re
import sys
import warnings

from Crypto.Cipher import AES
from termcolor import colored

DPAPI_PREFIX = b'\x01\x00\x00\x00'
APPBOUND_PREFIX = b'\x76\x32\x30\xfc'

warnings.filterwarnings("ignore")

try:
    from dpapick3 import blob, masterkey
except ImportError:
    raise ImportError("Missing dpapick3, please install via `pip install dpapick3`")


def parse_args():
    print(colored('[INFO] Welcome. To decrypt, one of the four following combinations is required:', 'yellow'))
    print("""	(1) Masterkey-file, SID and User-Pwd (or Hash)
        (2) Decrypted Masterkey
	(3) File containing decrypted Masterkeys
	(4) Masterkey-file and Domain PVK
    """)
    print(colored("[INFO] Needed files can be found here:", 'yellow'))
    print("""	Local State: \t%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Local State
	Passwords: \t%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Default\\Login Data
	Cookies: \t%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Default\\Login Data\\Network\\Cookies
	Masterkey(s): \t%appdata%\\Microsoft\\Protect\\S-1-5-21...-folder
    """)

    parser = argparse.ArgumentParser(description="Decrypt Chromium-based browser credentials and cookies")

    parser.add_argument('-t', '--statefile', metavar="", default='Local State', help='Path to "Local State" file')
    parser.add_argument('-l', '--loginfile', metavar="",help='Path to "Login Data" SQLite DB')
    # parser.add_argument('-c', '--cookies', metavar="",help='Path to Cookies file (optional)')
    parser.add_argument('-k', '--masterkey', metavar="",help='Direct Masterkey (128 hex chars or SHA1)')
    parser.add_argument('-f', '--masterkeylist', metavar="",help='File containing Masterkeys')
    parser.add_argument('-m', '--mkfile', metavar="",help='Masterkey GUID file or directory')
    parser.add_argument('-s', '--sid', metavar="",help='User SID')
    parser.add_argument('-a', '--pwdhash', metavar="",help='SHA1 password hash')
    parser.add_argument('-p', '--password', metavar="",help='User password')
    parser.add_argument('-r', '--pvk', metavar="",help='Domain PVK file')
    parser.add_argument('-o', '--export', metavar="",help='Export decrypted values to CSV')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='Verbose output')

    args = parser.parse_args()

    required_files = [
        (args.statefile, 'Local State'),
        (args.loginfile, 'Login Data'),
        # (args.cookies, 'Cookies'),
        (args.masterkeylist, 'Masterkey list'),
        (args.pvk, 'PVK file')
    ]

    for filepath, desc in required_files:
        if filepath and not os.path.isfile(filepath):
            sys.exit(colored(f"[-] Error: \"{desc}\"-file not found: {filepath}", "red"))

    if args.mkfile:
        args.mkfile = args.mkfile.replace('*', '')
        if not os.path.exists(args.mkfile):
            sys.exit(colored(f"[-] Error: mkfile not found: {args.mkfile}", "red"))
        if not args.sid:
            match = re.search(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", args.mkfile)
            if match:
                args.sid = match.group()
                print(colored(f"[+] Detected SID: {args.sid}", 'green'))

    if args.mkfile and args.sid and not args.password and not args.pwdhash:
        args.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        # On older systems: args.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0'
        print('[+] No password provided, using empty hash')

    if args.pwdhash:
        args.pwdhash = bytes.fromhex(args.pwdhash)

    return args


def parse_local_state(local_state_file):
    try:
        with open(local_state_file, "r") as file:
            local_state = json.load(file)
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return blob.DPAPIBlob(encrypted_key)
    except Exception as e:
        sys.exit(colored(f"[-] Error reading \"Local State\"-file: {e}", 'red'))


def parse_login_file(filepath, guid_list):
    logins = []
    try:
        with sqlite3.connect(filepath) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value, id FROM logins')
        for url, user, pwd, login_id in cursor.fetchall():
            if pwd[:4] == b'\x01\x00\x00\x00':
                parsed_blob = blob.DPAPIBlob(pwd)
                if parsed_blob.mkguid not in guid_list:
                    guid_list.append(parsed_blob.mkguid)
            logins.append((url, user, pwd, login_id))
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
                if note_blob[:4] == b'\x01\x00\x00\x00':
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
    except:
        pass
    return None


def decryptChromeString(data, bme_key, masterkeys, verbose=False):
    if data[:4] == DPAPI_PREFIX:
        for bMK in masterkeys:
            pb = blob.DPAPIBlob(data)
            pb.decrypt(bMK)
            if pb.decrypted:
                return pb.cleartext.decode(errors='ignore')
    elif data[:4] == APPBOUND_PREFIX:
        return colored("Unsupported AppBoundEncryption", 'red')
    else:
        try:
            iv = data[3:15]
            payload = data[15:]
            cipher = AES.new(bme_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)
            return decrypted[:-16].decode(errors='ignore')
        except Exception:
            if verbose:
                print(colored("[-] Error decrypting, maybe Browser Engine < v80", 'red'))
    return None


def decryptLogins(items, bme_key, masterkeys, csvfile=None, verbose=False, label='Credential'):
    count = 0
    if csvfile and label == 'Credential':
        with open(f'{label.lower()}_{csvfile}', 'a') as f:
            f.write(f"ID;URL;Username;Password\n")

    for item in items:
        data = decryptChromeString(item[2], bme_key, masterkeys)
        if verbose:
            print('ID:        {}'.format(item[3]))
            print('URL:       {}'.format(item[0]))
            print('User Name: {}'.format(item[1]))
            print('Password:  {}'.format(data))
            print('*' * 50)
        if data is not None:
            count += 1
        if csvfile:
            with open(f'{label.lower()}_{csvfile}', 'a') as f:
                if label == 'Credential':
                    f.write(f"{item[3]};{item[0]};{item[1]};{data}\n")
                else:
                    f.write('Note\n')
    return count


def decryptNotes(notes, bme_key, masterkeys, guid_list, csvfile=None, verbose=False):
    count = 0
    if csvfile:
        with open('notes_' + csvfile, 'a') as f:
            f.write('Note\n')
            
    for note in notes:
        note_decrypted = decryptChromeString(note, bme_key, masterkeys)
        if verbose:
            print('Note:  {}'.format(note_decrypted))
            print('*' * 50)
        if note_decrypted is not None:
            count += 1
        if csvfile:
            with open('notes_' + csvfile, 'a') as f:
                f.write('{}\n'.format(note_decrypted))
    return count


def process_masterkeys(args, local_state_blob):
    masterkeys = []
    masterkey_blob = None
    mkp = None

    # Option 1: Direct masterkey
    if args.masterkey:
        print('[!] Trying direct masterkey')
        masterkey_blob = bytes.fromhex(args.masterkey)

    # Option 1b: List of masterkeys
    elif args.masterkeylist:
        print('[!] Trying list of masterkeys')
        with open(args.masterkeylist) as f:
            masterkeys = [bytes.fromhex(line.strip()) for line in f if len(line.strip()) in (40, 128)]

    # Load masterkey pool if needed
    if args.mkfile:
        mkp = masterkey.MasterKeyPool()
        if os.path.isfile(args.mkfile):
            mkp.addMasterKey(open(args.mkfile, 'rb').read())
        else:
            mkp.loadDirectory(args.mkfile)
            if args.verbose:
                print(f'[!] Loaded {len(mkp.keys)} masterkey(s).')

    # Option 2: PVK domain key
    if mkp and args.pvk:
        print('[!] Trying MasterKey decryption with the PVK domain key')
        if mkp.try_domain(args.pvk) > 0:
            for mk_guid in list(mkp.keys):
                mk = mkp.getMasterKeys(mk_guid)[0]
                if mk.decrypted:
                    if mk.get_key() not in masterkeys:
                        masterkeys.append(mk.get_key())
                    if mk_guid.decode(errors='ignore') == local_state_blob.mkguid:
                        masterkey_blob = mk.get_key()
                        print('[+] Success, user Masterkey decrypted: ' + masterkey_blob.hex())

    # Option 3: User SID + password
    if args.mkfile and args.sid and (args.password or args.pwdhash):
        print('[!] Trying decryption of Masterkey with user-SID and password...')
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
                    print(colored(f'[!] Successfully decrypted user MasterKey: ' + masterkey_blob.hex(), 'green'))

    return masterkey_blob, masterkeys, mkp

def main():
    args = parse_args()
    guid_list, items, masterkeys = [], [], []
    bme_key = None

    ## Parse Local State file: search required masterkey-GUID
    local_state_blob = parse_local_state(args.statefile)
    print(colored(f"[+] \"Local State\" uses masterkey-GUID: {local_state_blob.mkguid}", 'green'))
    guid_list.append(local_state_blob.mkguid)

    ## Get Logins and Notes, if any
    if args.loginfile:
        items, guid_list = parse_login_file(args.loginfile, guid_list)
        print(f'[!] Found {len(items)} credential(s) in "Login Data".')
        notes, guid_list = parse_notes(args.loginfile, guid_list)
        print(f'[!] Found {len(notes)} note(s) in "Login Data".')
    else:
        sys.exit(colored('[-] Error: No \"Login Data\"-file provided. Exiting...', 'red'))

    ## If no decryption details are provided, feed results back
    if not args.masterkey and not args.masterkeylist and not args.mkfile:
        if len(guid_list) > 1:
            guid_list.sort()
            print('[!] Found {len(guid_list)} different Masterkeys, required for decrypting all logins and/or cookies:')
            for sGUID in guid_list:
                print('    ' + sGUID)
        print('[!] Input the masterkey-files and accompanying decryption details to continue decrypting')
        exit(0)

    print(colored('\n[INFO] Extracting Browser Master Encryption key from \"Local State\"', 'yellow'))


    # Process masterkeys based on provided arguments
    masterkey_blob, masterkeys_list, mkp = process_masterkeys(args, local_state_blob)
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
        print(colored(f'[+] Successfully got Browser Master Encryption key: {bme_key.hex()}', 'green'))
    else:
        print(colored(f'[-] Error decrypting Browser Master Encryption key. Is the (correct) password provided ?', 'red'))
        exit(0)

    ## Decrypt
    if args.loginfile:
        print(colored('\n[INFO] Decrypting logins from \"Login Data\"....', 'yellow'))
        decrypted = decryptLogins(items, bme_key, masterkeys, args.export, args.verbose, 'Credential')
        print(f'[!] Decrypted {decrypted} out of {len(items)} credentials\n')

    ## Decrypting Notes
        print(colored('[INFO] Decrypting notes....', 'yellow'))
        print('*' * 50)
        if bme_key and notes:
            count = decryptNotes(notes, bme_key, masterkeys, guid_list, args.export, args.verbose)
            print(f'[!] Decrypted {count}/{len(notes)} notes')

    ## Display deleted logins as bonus
    if args.loginfile:
        database = sqlite3.connect(args.loginfile)
        with database:
            for values in database.execute('SELECT origin_domain, username_value FROM stats'):
                print(colored("[BONUS-DELETED LOGIN]: ", 'yellow'))
                print(values[0], "\t", values[1])


if __name__ == '__main__':
    main()
