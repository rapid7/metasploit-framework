#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
#2018-05-09 14-15

# Standard Modules
import logging

# Extra Modules
dependencies_missing = False
try:
    import teradata
except ImportError:
    dependencies_missing = True

from metasploit import module


# Metasploit Metadata
metadata = {
    'name': 'Teradata ODBC SQL Query Module',
    'description': '''
        SQL query module for ODBC connections to local Teradata databases.

        Port specification (TCP 1025 by default) is not necessary for ODBC connections.

        Requires ODBC driver and Python Teradata module.
    ''',
    'authors': [
        'Ted Raffle (actuated)'
    ],
    'date': '2018-03-29',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://developer.teradata.com/tools/reference/teradata-python-module'},
        {'type': 'url', 'ref': 'https://downloads.teradata.com/download/connectivity/odbc-driver/linux'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Host to target', 'required': True},
        'rport': {'type': 'port', 'description': 'Port to target, ignored by the ODBC driver', 'required': True, 'default': 1025},
        'username': {'type': 'string', 'description': 'Username', 'required': True, 'default': 'dbc'},
        'password': {'type': 'string', 'description': 'Password', 'required': True, 'default': 'dbc'},
        'sql': {'type': 'string', 'description': 'SQL query to perform', 'required': True, 'default': 'SELECT DATABASENAME FROM DBC.DATABASES'},
    },
    'notes': {
        'AKA': ['Teradata ODBC Authentication Scanner']
    }
}


# Run function
def run(args):

    # Define UdaExec ODBC connection "application", must be before LogHandler
    udaExec = teradata.UdaExec(appName="Auth", version="1.0", logConsole=False, configureLogging=False)

    # Metasploit LogHandler
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))

    # Return error for missing dependency
    if dependencies_missing:
        logging.error('Python Teradata module missing, cannot continue')
        return

    # Set variables to current RHOST, and USERNAME and PASSWORD options
    host = args['rhost']
    user = args['username']
    password = args['password']

    # Perform login attempt
    module.log(host + ' - ' + user + ':' + password + ' - Starting')
    try:
        session = udaExec.connect(method="odbc", system=host, username=user, password=password);
    except teradata.api.Error as e:
        logging.error(user + ':' + password + ' - ' + format(e))
        return
    else:
        module.log(host + ' - ' + user + ':' + password + ' - Login Successful', level='good')
        try:
            query = args['sql']
            module.log(host + ' - Starting - ' + query)
            for row in session.execute(query):
                outputRow=str(row)
                module.log(host + ' - ' + outputRow, level='good')
        except teradata.api.Error as e:
            logging.error(format(e))
            return


if __name__ == '__main__':
    module.run(metadata, run)
