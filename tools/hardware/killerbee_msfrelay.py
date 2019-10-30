#!/usr/bin/env python
# KillerBee Metasploit relay server

import re
import os
import sys
import cmd
import time
import json
import base64
import socket
import threading
import pkg_resources # Used to get killerbee version

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from urlparse import parse_qs,urlparse
from killerbee import *

last_errors = 0
starttime = 0
packets_sent = 0
last_sent = 0
username = None
password = None
kb = None

class MSFHandler(BaseHTTPRequestHandler):
    def status(self):
        status = {}
        hw_versions = []
        fw_version = pkg_resources.get_distribution("killerbee").version
        device_names = []
        for dev in kbutils.devlist():
            hw_versions.append(dev[2])
            device_names.append(dev[1])
        if len(hw_versions) > 0:
            status["operational"] = 1
        else:
            status["operational"] = 0
        status["hw_specialty"] = { "zigbee": True }
        # TODO: We should check firmware before reporting transmit capabilities
        status["hw_capabilities"] = { "transmit": True}
        status["last_10_errors"] = last_errors
        status["api_version"] = "0.0.3"
        status["fw_version"] = fw_version
        if len(hw_versions) == 1:
            status["hw_version"] = hw_versions[0]
            status["device_name"] = device_names[0]
        elif len(hw_versions) > 1:
            status["hw_version"] = ', '.join(hw_versions)
            status["device_name"] = ', '.join(device_names)
        else:
            status["hw_version"] = "Not Supported"
        return status

    def statistics(self):
        global packets_sent
        stats = {}
        stats["uptime"] = int(time.time()) - starttime
        stats["packet_stats"] = packets_sent
        stats["last_request"] = last_sent
        stats["voltage"] = "0.0v"
        return stats

    def datetime(self):
        return { "sytem_datetime": int(time.time()) }

    def timezone(self):
        return { "system_timezone": time.strftime("%Z") }

    def set_channel(self, args):
        if not "chan" in args:
            return self.not_supported()
        chan = int(args["chan"][0])
        kb.set_channel(chan)
        return { "success": True }

    def inject(self, args):
        global packets_sent
        if not "data" in args:
            return self.not_supported()
        try:
            kb.inject(base64.urlsafe_b64decode(args["data"][0]))
            packets_sent+=1
        except Exception, e:
            print("ERROR: Unable to inject packet: {0}".format(e))
            return { "success": False }
        return { "success": True }

    def recv(self):
        pkt = kb.pnext()
        if pkt != None and pkt[1]:
            return {"data": base64.urlsafe_b64encode(pkt[0]), "valid_crc": pkt[1], "rssi": pkt[2] }
        return {}

    def sniffer_off(self):
        kb.sniffer_off()
        return {"success": True }

    def sniffer_on(self):
        kb.sniffer_on()
        return {"success": True }

    def supported_devices(self):
        devices = []
        for dev in kbutils.devlist():
          devices.append(dev[0])
        return { "devices": devices }

    def not_supported(self):
        return { "status": "not supported" }

    def send(self, data, resp=200):
        self.send_response(resp)
        self.send_header('Content-type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data))
        return

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Killerbee MSF Relay\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write("Please Authenticate")
        
    def do_GET(self):
        if not password == None:
            if self.headers.getheader('Authorization') == None:
                print("Did not authenticate")
                self.do_AUTHHEAD()
                return
            if not self.headers.getheader('Authorization') == 'Basic '+base64.b64encode(username + ":" + password):
                print("Bad Authentication")
                self.do_AUTHHEAD()
                return
        url = urlparse(self.path)
        args = parse_qs(url.query)
        if self.path=="/status":
            self.send(self.status())
        elif self.path=="/statistics":
            self.send(self.statistics())
        elif self.path=="/settings/datetime":
            self.send(self.datetime())
        elif self.path=="/settings/timezone":
            self.send(self.timezone())
        elif self.path=="/zigbee/supported_devices":
            self.send(self.supported_devices())
        elif self.path.startswith("/zigbee/"):
            re_dev = re.compile("/zigbee/([\d\w:]+)/")
            m = re_dev.match(self.path)
            if m:
                dev = m.group(1)
                if self.path.find("/set_channel?") > -1:
                    self.send(self.set_channel(args))
                elif self.path.find("/inject?") > -1:
                    self.send(self.inject(args))
                elif self.path.find("/recv") > -1:
                    self.send(self.recv())
                elif self.path.find("/sniffer_off") > -1:
                    self.send(self.sniffer_off())
                elif self.path.find("/sniffer_on") > -1:
                    self.send(self.sniffer_on())
                else:
                    self.send(self.not_supported(), 404)
            else:
                self.send(self.not_supported(), 404)
        else:
            self.send(self.not_supported(), 404)
        return

class Killerbee_MSFRelay(cmd.Cmd):
    intro = """
       KillerBee Metasploit Relay
"""

    def __init__(self, ip='0.0.0.0', port=8080):
        cmd.Cmd.__init__(self)

        self._ip = ip
        self._port = port
        self._sock = None
        self._pause = False

        self.start()

    def start(self):
        self._go = True
        while self._go:
            # serve the NIC port
            try:
                self._sock = HTTPServer((self._ip, self._port), MSFHandler)
                starttime = int(time.time())
                print("KillerBee MSFRelay running.")
                self._sock.serve_forever()
            except KeyboardInterrupt:
                self._sock.socket.close()
                self._go = False
            except:
                sys.excepthook(*sys.exc_info())

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', '--dev', action='store', dest='devstring')
    parser.add_argument('-u', '--user', default="msf_relay", help='HTTP Username', type=str)
    parser.add_argument('-p', '--password', default="rfcat_relaypass", help='HTTP Password', type=str)
    parser.add_argument('-P', '--Port', default=8080, type=int)
    parser.add_argument('--noauth', default=False, action="store_true", help='Do not require authentication')
    parser.add_argument('--localonly', default=False, action="store_true", help='Listen on localhost only')

    ifo = parser.parse_args()

    try:
        kb = KillerBee(device=ifo.devstring)
    except KBInterfaceError as e:
        print("Interface Error: {0}".format(e))
        sys.exit(-1)

    username = ifo.user
    password = ifo.password
    ip = "0.0.0.0"
    port = ifo.Port
    if ifo.noauth:
         username = None
         password = None
    if ifo.localonly:
         host = "127.0.0.1"

    wait_msg = False
    dev_found = False
    while not dev_found:
        try:
            devs = kbutils.devlist()
            if len(devs) > 0:
                dev_found = True
            elif not wait_msg:
                print("Insert KillerBee compatible ZigBee device.  (You may need to add permissions)")
                wait_msg = True
        except KeyboardInterrupt:
            sys.exit()
        except:
            if not wait_msg:
                print("Insert KillerBee compatible ZigBee device.  (You may need to add permissions)")
                wait_msg = True

    beerelay = Killerbee_MSFRelay(ip, port)
    
import atexit
atexit.register(cleanupInteractiveAtExit)
