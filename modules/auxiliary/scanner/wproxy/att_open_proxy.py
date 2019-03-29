#!/usr/bin/env python3

from metasploit import module, probe_scanner


metadata = {
    'name': 'Open WAN-to-LAN proxy on AT&T routers',
    'description': '''
        The Arris NVG589 and NVG599 routers configured with AT&T U-verse
        firmware 9.2.2h0d83 expose an un-authenticated proxy that allows
        connecting from WAN to LAN by MAC address.
     ''',
    'authors': [
        'Joseph Hutchins' # Initial disclosure
        'Jon Hart <jon_hart[AT]rapid7.com>', # Dummy payload and response pattern
        'Adam Cammack <adam_cammack[AT]rapid7.com>' # Metasploit module
    ],
    'date': '2017-08-31',
    'references': [
        {'type': 'cve', 'ref': '2017-14117'},
        {'type': 'url', 'ref': 'https://www.nomotion.net/blog/sharknatto/'},
        {'type': 'url', 'ref': 'https://blog.rapid7.com/2017/09/07/measuring-sharknat-to-exposures/#vulnerability5port49152tcpexposure'}
     ],
    'type': 'multi_scanner',
    'options': {
        'rhosts': {'type': 'address_range', 'description': 'The target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'The target port', 'required': True, 'default': 49152},
     },
     'notes': {
         'AKA': [
            'SharknAT&To',
            'sharknatto'
         ]
     }
    }


def report_wproxy(target, response):
    # We don't use the response here, but if we were a banner scraper we could
    # print or report it
    module.report_vuln(target[0], 'wproxy', port=target[0])


if __name__ == "__main__":
    study = probe_scanner.make_scanner(
        # Payload and pattern are given and applied straight to the socket, so
        # they need to be bytes-like
        payload=b'\x2a\xce\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        pattern=b'^\\*\xce.{3}$',
        onmatch=report_wproxy
    )
    module.run(metadata, study)
