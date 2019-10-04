#!/usr/bin/env python3

# urgent11-detector - IPnet detection tool
# Copyright (C) 2019 Armis Security.
# Research paper: https://armis.com/urgent11
# License: https://www.gnu.org/licenses/agpl-3.0.txt

metadata = {
    'name': 'urgent11-detector - IPnet detection tool by Armis',
    'description': """
        This tool implements 4 unique methods of detection
        in the form of a TCP/IP stack fingerprints to a target host.
        By calculating the sum of all the methods scores, we can determine with
        high precision whether the target host runs some embedded OS
        that relies on the IPnet TCP/IP stack and whether that OS is VxWorks.

        Moreover we test the host for one of the URGENT/11 vulnerabilities,
        CVE-2019-12258.
    """,
    'authors': [
        'Ben Seri' # Upstream tool
        'Brent Cook' # Metasploit module
    ],
    'date': '2019-09-19',
    'references': [
        {'type': 'cve', 'ref': '2019-12256'},
        {'type': 'cve', 'ref': '2019-12257'},
        {'type': 'cve', 'ref': '2019-12255'},
        {'type': 'cve', 'ref': '2019-12260'},
        {'type': 'cve', 'ref': '2019-12261'},
        {'type': 'cve', 'ref': '2019-12263'},
        {'type': 'cve', 'ref': '2019-12258'},
        {'type': 'cve', 'ref': '2019-12259'},
        {'type': 'cve', 'ref': '2019-12262'},
        {'type': 'cve', 'ref': '2019-12264'},
        {'type': 'cve', 'ref': '2019-12265'},
    ],
    'type': 'single_scanner',
    'options':  {
        'rport': {'type': 'port', 'description': 'The target port', 'required': True, 'default': 80},
    },
    'notes': {
        'AKA': [
            'Urgent/11'
            ]
    }
}

import abc
import argparse
import contextlib
import socket
import struct
import sys

import metasploit.module as module

try:
    if sys.platform == 'linux' or sys.platform == 'linux2':
        import iptc
    from scapy.all import sr1, ICMP, IP, TCP
except ImportError:
    dependencies_missing = True
else:
    dependencies_missing = False

# Config
CFG_PACKET_TIMEOUT = 0.5
CFG_RETRANSMISSION_RATE = 3

# Consts
TCP_OPTION_NOP = 1
TCP_OPTION_MSS = 2
TCP_OPTION_WNDSCL = 3
TCP_RST_FLAG = 'R'
TCP_SYN_FLAG = 'S'
ICMP_TIMESTAMP_REPLY = 14
ICMP_ECHO_REQUEST = 8
ICMP_TIMESTAMP_REQUEST_TRUNCATED = bytes.fromhex('0d00f2ff00000000')


# Utility functions
@contextlib.contextmanager
def iptables_block_port(port):
    """Add an iptables rule in order to prevent host system to answer our packets.

    This should NEVER be called with user input!
    """
    iptables_rule = {'protocol': 'tcp',
                     'target': 'DROP',
                     'tcp': {'dport': port}}
    if sys.platform == 'linux' or sys.platform == 'linux2':
        try :
            iptc.easy.insert_rule('filter', 'INPUT', iptables_rule)
            yield
        finally:
            iptc.easy.delete_rule('filter', 'INPUT', iptables_rule)
    else:
        yield


@contextlib.contextmanager
def bind_random_port():
    """Bind a random free port on all interfaces for our probing.

    we do that in order to promise we wont block an actual service
    from working on the server by accident.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_catcher:
        port_catcher.bind(('', 0))
        port_catcher.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        yield port_catcher.getsockname()[1]


@contextlib.contextmanager
def get_safe_src_port():
    with bind_random_port() as port, iptables_block_port(port):
        yield port


def is_port_reachable(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(CFG_PACKET_TIMEOUT)
        return conn.connect_ex((ip, port)) == 0


def validate_flags(pkt, flags):
    return flags in pkt['TCP'].flags


def validate_ports(pkt, src, dst):
    return pkt['TCP'].sport == src and pkt['TCP'].dport == dst


class DetectionMethod(abc.ABC):
    """Base-class for a detection method.

    should only be inherited and never instantiated.
    """
    def __init__(self, target):
        super().__init__()
        self._target = target
        self.vxworks_score = 0
        self.ipnet_score = 0
        self.vulnerable_cves = []

    @abc.abstractmethod
    def detect(self, dst_port):
        """This method implements the actual detection logic.

        It should set relevant class members:
        vxworks_score, ipnet_score, vulnerable_cves to a number between
        -100 to 100 that indicates certainty level or leave untouched if unsure
        This method should run only once during the life on a
        sub-class instance, due to the fact that it changes public members.
        """
        pass


class TcpMalformedOptionsDetection(DetectionMethod):
    """This method relies on the fact that upon parsing a malformed TCP option.

    IPnet will drop the packet and in the IPnet version used by VxWorks,
    a RST packet will be returned as well.
    While a different device (from our testing),
    will just ignore the malformed option an go on to parse the valid one.
    """

    def detect(self, dst_port):
        with get_safe_src_port() as src_port:
            for _ in range(CFG_RETRANSMISSION_RATE):
                # We start by adding normal TCP Options
                tcp_options = [(TCP_OPTION_MSS, struct.pack('>H', 1460)),
                               (TCP_OPTION_NOP, b''),
                               # WNDSCL option with invalid length,
                               # followed by a valid one:
                               (TCP_OPTION_WNDSCL, b''),
                               (TCP_OPTION_WNDSCL, b'\0')]

                pkt = IP(dst=self._target) / TCP(sport=src_port,
                                                 dport=dst_port,
                                                 flags=TCP_SYN_FLAG,
                                                 options=tcp_options)
                response = sr1(pkt, verbose=False, timeout=CFG_PACKET_TIMEOUT)
                if response is not None:
                    break

            if response is None:
                self.vxworks_score = 0
                self.ipnet_score = 50
            elif (validate_flags(response, TCP_RST_FLAG) and
                  validate_ports(response, dst_port, src_port)):
                self.vxworks_score = 100
                self.ipnet_score = 100
            else:
                self.vxworks_score = -100
                self.ipnet_score = -100


class TcpDosDetection(DetectionMethod):
    """This method relies on the fact that upon parsing a malformed TCP option.

    IPnet will drop the packet and respond with an RST
    without checking the sequences.
    In fact, this is an harmless exploitation of CVE-2019-12258.
    """

    def detect(self, dst_port):
        # Establish a valid connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with contextlib.closing(sock) as legitimate_connection:
            legitimate_connection.settimeout(CFG_PACKET_TIMEOUT)
            legitimate_connection.connect((self._target, dst_port))
            _, src_port = legitimate_connection.getsockname()
            _, dst_port = legitimate_connection.getpeername()

            # DoS the connection using CVE-2019-12258
            for _ in range(CFG_RETRANSMISSION_RATE):
                # Malformed tcp options
                tcp_options = [(TCP_OPTION_WNDSCL, b'')]
                pkt = IP(dst=self._target) / TCP(sport=src_port,
                                                 dport=dst_port,
                                                 seq=0x4141,
                                                 ack=0x4141,
                                                 flags='S',
                                                 options=tcp_options)
                response = sr1(pkt, verbose=False, timeout=CFG_PACKET_TIMEOUT)

                if response is not None:
                    break

            # Check whether we managed to exploit CVE-2019-12258
            if response is None:
                self.vxworks_score = 0
                self.ipnet_score = 0
            elif (validate_flags(response, TCP_RST_FLAG) and
                  validate_ports(response, dst_port, src_port)):
                self.vxworks_score = 100
                self.ipnet_score = 100
                self.vulnerable_cves = ['CVE-2019-12258']
            else:
                self.vxworks_score = 0
                self.ipnet_score = 0


class IcmpCodeDetection(DetectionMethod):
    """This method relies on the fact that IPnet zero's out the ICMP code field.

    Even when it is not relevant to the packet.
    The ICMP Code field has no meaning in an echo request.
    """

    def detect(self, dst_port):
        pkt = IP(dst=self._target) / ICMP(type=ICMP_ECHO_REQUEST, code=0x41)
        response = sr1(pkt, verbose=False, timeout=CFG_PACKET_TIMEOUT)

        if response is None:
            self.ipnet_score = 0
        elif response['ICMP'].code == 0:
            self.ipnet_score = 20
        else:
            self.ipnet_score = -20


class IcmpTimestampDetection(DetectionMethod):
    """This method relies on an implementation bug inside of the IPnet stack.

    when an ICMP timestamp request is parsed,
    it is answered even if the packet is truncated.
    Most OS's wont answer that request, let alone if it is truncated.
    """

    def detect(self, dst_port):
        pkt = IP(dst=self._target) / ICMP(ICMP_TIMESTAMP_REQUEST_TRUNCATED)
        response = sr1(pkt, verbose=False, timeout=CFG_PACKET_TIMEOUT)

        if response is None:
            self.ipnet_score = 0
        elif response['ICMP'].type == ICMP_TIMESTAMP_REPLY:
            self.ipnet_score = 90
        else:
            self.ipnet_score = -30


# CLI Logic
def run_detections(ip, port):
    detections = []
    for detection_cls in DetectionMethod.__subclasses__():
        detections.append(detection_cls(ip))

    module.log('Running against %s:%d' % (ip, port))

    final_ipnet_score = 0
    final_vxworks_score = 0
    affected_vulnerabilities = []

    for detection in detections:
        detection.detect(port)
        name = type(detection).__name__
        final_ipnet_score += detection.ipnet_score
        final_vxworks_score += detection.vxworks_score
        affected_vulnerabilities += detection.vulnerable_cves
        module.log('\t%-30s\tVxWorks: %s\tIPnet: %s' % (name,
                                                   detection.vxworks_score,
                                                   detection.ipnet_score))

    if final_ipnet_score > 0:
        module.log('IP %s detected as IPnet' % ip)
    elif final_ipnet_score < 0:
        module.log('IP %s detected as NOT IPnet' % ip)

    if final_vxworks_score > 100:
        module.log('IP %s detected as VxWorks' % ip)
    elif final_vxworks_score < 0:
        module.log('IP %s detected as NOT VxWorks' % ip)

    for vulnerability in affected_vulnerabilities:
        module.report_vuln(ip, vulnerability, port = port)
        module.log('IP %s affected by %s' % (ip, vulnerability))

def main(args):
    if dependencies_missing:
        module.log('Module dependencies (python-iptables, scapy) missing, cannot continue', level='error')
        return
    args['rport'] = int(args['rport'])

    if not is_port_reachable(args['rhost'], args['rport']):
        module.log('Target IP or port is unreachable, please verify input')
        return

    run_detections(args['rhost'], args['rport'])

if __name__ == '__main__':
    module.run(metadata, main)
