#!/usr/bin/env python
# -*- coding: utf-8 -*-
#2018-05-29 08-49

# Standard Modules
import logging

# Extra Modules
dependencies_missing = False
try:
    import teradata
except ImportError:
    dependencies_missing = True

from metasploit import module, login_scanner


# Metasploit Metadata
metadata = {
    'name': 'Teradata ODBC Login Scanner Module',
    'description': '''
        Login scanner module for ODBC connections to Teradata databases.

        Port specification (TCP 1025 by default) is not necessary for ODBC connections.

        Blank passwords are not supported by ODBC connections.

        Requires ODBC driver and Python Teradata module.
    ''',
    'authors': [
        'Ted Raffle (actuated)'
    ],
    'date': '2018-03-30',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://developer.teradata.com/tools/reference/teradata-python-module'},
        {'type': 'url', 'ref': 'https://downloads.teradata.com/download/connectivity/odbc-driver/linux'}
    ],
    'type': 'single_host_login_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Host to target', 'required': True},
        'rport': {'type': 'port', 'description': 'Port to target, ignored by the ODBC driver', 'required': True, 'default': 1025},
        'userpass': {'type': 'string', 'description': 'A list of username/password combinations to try', 'required': False},
        'sleep_interval': {'type': 'float', 'description': 'Time in seconds to wait between login attempts', 'required': False}
    },
    'service_name': 'teradata',
    'notes': {
        'AKA': ['Teradata ODBC Login Scanner']
    }
}


def valid_login(udaExec, host, user, password):
    try:
        udaExec.connect(method="odbc", system=host, username=user, password=password)
    except teradata.api.Error as e:
        return False
    else:
        return True


def run(args):
    if dependencies_missing:
        module.log('Python Teradata module missing, cannot continue', level=error)
        return

    # Define UdaExec ODBC connection "application" globally, must be before LogHandler
    udaExec = teradata.UdaExec(appName="Auth", version="1.0", logConsole=False, configureLogging=False)
    module.LogHandler.setup(msg_prefix='{}:{} - '.format(args['rhost'], 1025))
    scanner = login_scanner.make_scanner(lambda host, port, username, password: valid_login(udaExec, host, username, password))
    scanner(args)


if __name__ == '__main__':
    module.run(metadata, run)
