# -*- coding: binary -*-
module Rex
module Proto
module SMB
class Constants

require 'rex/struct2'

# SMB Commands
SMB_COM_CREATE_DIRECTORY           = 0x00
SMB_COM_DELETE_DIRECTORY           = 0x01
SMB_COM_OPEN                       = 0x02
SMB_COM_CREATE                     = 0x03
SMB_COM_CLOSE                      = 0x04
SMB_COM_FLUSH                      = 0x05
SMB_COM_DELETE                     = 0x06
SMB_COM_RENAME                     = 0x07
SMB_COM_QUERY_INFORMATION          = 0x08
SMB_COM_SET_INFORMATION            = 0x09
SMB_COM_READ                       = 0x0a
SMB_COM_WRITE                      = 0x0b
SMB_COM_LOCK_BYTE_RANGE            = 0x0c
SMB_COM_UNLOCK_BYTE_RANGE          = 0x0d
SMB_COM_CREATE_TEMPORARY           = 0x0e
SMB_COM_CREATE_NEW                 = 0x0f
SMB_COM_CHECK_DIRECTORY            = 0x10
SMB_COM_PROCESS_EXIT               = 0x11
SMB_COM_SEEK                       = 0x12
SMB_COM_LOCK_AND_READ              = 0x13
SMB_COM_WRITE_AND_UNLOCK           = 0x14
SMB_COM_READ_RAW                   = 0x1a
SMB_COM_READ_MPX                   = 0x1b
SMB_COM_READ_MPX_SECONDARY         = 0x1c
SMB_COM_WRITE_RAW                  = 0x1d
SMB_COM_WRITE_MPX                  = 0x1e
SMB_COM_WRITE_MPX_SECONDARY        = 0x1f
SMB_COM_WRITE_COMPLETE             = 0x20
SMB_COM_QUERY_SERVER               = 0x21
SMB_COM_SET_INFORMATION2           = 0x22
SMB_COM_QUERY_INFORMATION2         = 0x23
SMB_COM_LOCKING_ANDX               = 0x24
SMB_COM_TRANSACTION                = 0x25
SMB_COM_TRANSACTION_SECONDARY      = 0x26
SMB_COM_IOCTL                      = 0x27
SMB_COM_IOCTL_SECONDARY            = 0x28
SMB_COM_COPY                       = 0x29
SMB_COM_MOVE                       = 0x2a
SMB_COM_ECHO                       = 0x2b
SMB_COM_WRITE_AND_CLOSE            = 0x2c
SMB_COM_OPEN_ANDX                  = 0x2d
SMB_COM_READ_ANDX                  = 0x2e
SMB_COM_WRITE_ANDX                 = 0x2f
SMB_COM_NEW_FILE_SIZE              = 0x30
SMB_COM_CLOSE_AND_TREE_DISC        = 0x31
SMB_COM_TRANSACTION2               = 0x32
SMB_COM_TRANSACTION2_SECONDARY     = 0x33
SMB_COM_FIND_CLOSE2                = 0x34
SMB_COM_FIND_NOTIFY_CLOSE          = 0x35
SMB_COM_TREE_CONNECT               = 0x70
SMB_COM_TREE_DISCONNECT            = 0x71
SMB_COM_NEGOTIATE                  = 0x72
SMB_COM_SESSION_SETUP_ANDX         = 0x73
SMB_COM_LOGOFF_ANDX                = 0x74
SMB_COM_TREE_CONNECT_ANDX          = 0x75
SMB_COM_QUERY_INFORMATION_DISK     = 0x80
SMB_COM_SEARCH                     = 0x81
SMB_COM_FIND                       = 0x82
SMB_COM_FIND_UNIQUE                = 0x83
SMB_COM_FIND_CLOSE                 = 0x84
SMB_COM_NT_TRANSACT                = 0xa0
SMB_COM_NT_TRANSACT_SECONDARY      = 0xa1
SMB_COM_NT_CREATE_ANDX             = 0xa2
SMB_COM_NT_CANCEL                  = 0xa4
SMB_COM_NT_RENAME                  = 0xa5
SMB_COM_OPEN_PRINT_FILE            = 0xc0
SMB_COM_WRITE_PRINT_FILE           = 0xc1
SMB_COM_CLOSE_PRINT_FILE           = 0xc2
SMB_COM_GET_PRINT_QUEUE            = 0xc3
SMB_COM_READ_BULK                  = 0xd8
SMB_COM_WRITE_BULK                 = 0xd9
SMB_COM_NO_ANDX_COMMAND            = 0xff


# SMB Version 2 Commands
SMB2_OP_NEGPROT   = 0x00
SMB2_OP_SESSSETUP = 0x01
SMB2_OP_LOGOFF    = 0x02
SMB2_OP_TCON      = 0x03
SMB2_OP_TDIS      = 0x04
SMB2_OP_CREATE    = 0x05
SMB2_OP_CLOSE     = 0x06
SMB2_OP_FLUSH     = 0x07
SMB2_OP_READ      = 0x08
SMB2_OP_WRITE     = 0x09
SMB2_OP_LOCK      = 0x0a
SMB2_OP_IOCTL     = 0x0b
SMB2_OP_CANCEL    = 0x0c
SMB2_OP_KEEPALIVE = 0x0d
SMB2_OP_FIND      = 0x0e
SMB2_OP_NOTIFY    = 0x0f
SMB2_OP_GETINFO   = 0x10
SMB2_OP_SETINFO   = 0x11
SMB2_OP_BREAK     = 0x12


# SMB_COM_NT_TRANSACT Subcommands
NT_TRANSACT_CREATE                   = 1 # File open/create
NT_TRANSACT_IOCTL                    = 2 # Device IOCTL
NT_TRANSACT_SET_SECURITY_DESC        = 3 # Set security descriptor
NT_TRANSACT_NOTIFY_CHANGE            = 4 # Start directory watch
NT_TRANSACT_RENAME                   = 5 # Reserved (Handle-based)
NT_TRANSACT_QUERY_SECURITY_DESC      = 6 # Retrieve security
NT_TRANSACT_GET_USER_QUOTA           = 7 # Get quota
NT_TRANSACT_SET_USER_QUOTA           = 8 # Set quota

# Open Modes
OPEN_MODE_CREAT = 0x10   # Create the file if file does not exists. Otherwise, operation fails.
OPEN_MODE_EXCL  = 0x00   # When used with SMB_O_CREAT, operation fails if file exists. Cannot be used with SMB_O_OPEN.
OPEN_MODE_OPEN  = 0x01   # Open the file if the file exists
OPEN_MODE_TRUNC = 0x02   # Truncate the file if the file exists

# Shared Access
OPEN_SHARE_COMPAT            = 0x00
OPEN_SHARE_DENY_EXCL         = 0x10
OPEN_SHARE_DENY_WRITE        = 0x20
OPEN_SHARE_DENY_READEXEC     = 0x30
OPEN_SHARE_DENY_NONE         = 0x40


# File Access
OPEN_ACCESS_READ          = 0x00
OPEN_ACCESS_WRITE         = 0x01
OPEN_ACCESS_READWRITE     = 0x02
OPEN_ACCESS_EXEC          = 0x03

# Create Disposition
CREATE_ACCESS_SUPERSEDE  = 0x00	# Replace any previously existing file
CREATE_ACCESS_EXIST      = 0x01 # Open existing file and fail if it does not exist
CREATE_ACCESS_CREATE     = 0x02 # Create the file, fail if it already exists
CREATE_ACCESS_OPENCREATE = 0x03 # Open existing file or create it if it does not exist
CREATE_ACCESS_OVEREXIST  = 0x04 # Overwrite existing file and fail if it does not exist
CREATE_ACCESS_OVERCREATE = 0x05 # Overwrite existing file or create it if it does not exist


# Wildcard NetBIOS name
NETBIOS_REDIR = 'CACACACACACACACACACACACACACACAAA'



	# 0 = open2
	# 1 = find_first
	# 2 = find_next
	# 3 = query_fs_info
	# 4 = set_fs_quota
	# 5 = query_path_info
	# 6 = set_path_info
	# 7 = query_file_info
	# 8 = set_file_info
	# 9 = fsctl
	# 10 = ioctl2
	# 11 = find_notify_first
	# 12 = find_notify_next
	# 13 = create_directory
	# 14 = session_setup


# SMB_COM_TRANSACTION2 Commands
TRANS2_OPEN2 = 0
TRANS2_FIND_FIRST2 = 1
TRANS2_FIND_NEXT2 = 2
TRANS2_QUERY_FS_INFO = 3
TRANS2_SET_PATH_INFO = 6

TRANS2_CREATE_DIRECTORY = 13

# SMB_COM_TRANSACTION2 QUERY_FS_INFO information levels
SMB_INFO_ALLOCATION = 1
SMB_INFO_VOLUME = 2
SMB_QUERY_FS_VOLUME_INFO = 0x102
SMB_QUERY_FS_SIZE_INFO = 0x103
SMB_QUERY_FS_DEVICE_INFO = 0x104
SMB_QUERY_FS_ATTRIBUTE_INFO = 0x105

# SMB_COM_TRANSACTION2 QUERY_PATH_INFO information levels
SMB_INFO_STANDARD = 1
SMB_INFO_QUERY_EA_SIZE = 2
SMB_INFO_QUERY_EAS_FROM_LIST = 3
SMB_INFO_QUERY_ALL_EAS = 4
SMB_INFO_IS_NAME_VALID = 6
SMB_QUERY_FILE_BASIC_INFO = 0x101
SMB_QUERY_FILE_STANDARD_INFO = 0x102
SMB_QUERY_FILE_EA_INFO = 0x103
SMB_QUERY_FILE_NAME_INFO = 0x104
SMB_QUERY_FILE_ALL_INFO = 0x107
SMB_QUERY_FILE_ALT_NAME_INFO = 0x108
SMB_QUERY_FILE_STREAM_INFO = 0x109
SMB_QUERY_FILE_COMPRESSION_INFO = 0x10B
SMB_QUERY_FILE_UNIX_BASIC = 0x200
SMB_QUERY_FILE_UNIX_LINK = 0x201
SMB_INFO_PASSTHROUGH = 0x1000


# Device Types
FILE_DEVICE_BEEP = 0x00000001
FILE_DEVICE_CD_ROM = 0x00000002
FILE_DEVICE_CD_ROM_FILE_SYSTEM = 0x00000003
FILE_DEVICE_CONTROLLER = 0x00000004
FILE_DEVICE_DATALINK = 0x00000005
FILE_DEVICE_DFS = 0x00000006
FILE_DEVICE_DISK = 0x00000007
FILE_DEVICE_DISK_FILE_SYSTEM = 0x00000008
FILE_DEVICE_FILE_SYSTEM = 0x00000009
FILE_DEVICE_INPORT_PORT = 0x0000000A
FILE_DEVICE_KEYBOARD = 0x0000000B
FILE_DEVICE_MAILSLOT = 0x0000000C
FILE_DEVICE_MIDI_IN = 0x0000000D
FILE_DEVICE_MIDI_OUT = 0x0000000E
FILE_DEVICE_MOUSE = 0x0000000F
FILE_DEVICE_MULTI_UNC_PROVIDER = 0x00000010
FILE_DEVICE_NAMED_PIPE = 0x00000011
FILE_DEVICE_NETWORK = 0x00000012
FILE_DEVICE_NETWORK_BROWSER = 0x00000013
FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014
FILE_DEVICE_NULL = 0x00000015
FILE_DEVICE_PARALLEL_PORT = 0x00000016
FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017
FILE_DEVICE_PRINTER = 0x00000018
FILE_DEVICE_SCANNER = 0x00000019
FILE_DEVICE_SERIAL_MOUSE_PORT = 0x0000001A
FILE_DEVICE_SERIAL_PORT = 0x0000001B
FILE_DEVICE_SCREEN = 0x0000001C
FILE_DEVICE_SOUND = 0x0000001D
FILE_DEVICE_STREAMS = 0x0000001E
FILE_DEVICE_TAPE = 0x0000001F
FILE_DEVICE_TAPE_FILE_SYSTEM = 0x00000020
FILE_DEVICE_TRANSPORT = 0x00000021
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_DEVICE_VIDEO = 0x00000023
FILE_DEVICE_VIRTUAL_DISK = 0x00000024
FILE_DEVICE_WAVE_IN = 0x00000025
FILE_DEVICE_WAVE_OUT = 0x00000026
FILE_DEVICE_8042_PORT = 0x00000027
FILE_DEVICE_NETWORK_REDIRECTOR = 0x00000028
FILE_DEVICE_BATTERY = 0x00000029
FILE_DEVICE_BUS_EXTENDER = 0x0000002A
FILE_DEVICE_MODEM = 0x0000002B
FILE_DEVICE_VDM = 0x0000002C

# File and Device Attributes
FILE_REMOVABLE_MEDIA = 0x00000001
FILE_READ_ONLY_DEVICE = 0x00000002
FILE_FLOPPY_DISKETTE = 0x00000004
FILE_WRITE_ONE_MEDIA = 0x00000008
FILE_REMOTE_DEVICE = 0x00000010
FILE_DEVICE_IS_MOUNTED = 0x00000020
FILE_VIRTUAL_VOLUME = 0x00000040
FILE_CASE_SENSITIVE_SEARCH = 0x00000001
FILE_CASE_PRESERVED_NAMES = 0x00000002
FILE_PERSISTENT_ACLS = 0x00000004
FILE_FILE_COMPRESSION = 0x00000008
FILE_VOLUME_QUOTAS = 0x00000010
FILE_VOLUME_IS_COMPRESSED = 0x00008000


# SMB Error Codes
SMB_STATUS_SUCCESS =			0x00000000
SMB_ERROR_BUFFER_OVERFLOW =		0x80000005
SMB_STATUS_MORE_PROCESSING_REQUIRED =	0xC0000016
SMB_STATUS_ACCESS_DENIED =		0xC0000022
SMB_STATUS_LOGON_FAILURE =		0xC000006D

# SMB Dialect Compatibility
DIALECT = {}

DIALECT['PC NETWORK PROGRAM 1.0'] = [
	SMB_COM_CHECK_DIRECTORY,
	SMB_COM_CLOSE,
	SMB_COM_CLOSE_PRINT_FILE,
	SMB_COM_CREATE,
	SMB_COM_CREATE_DIRECTORY,
	SMB_COM_CREATE_NEW,
	SMB_COM_CREATE_TEMPORARY,
	SMB_COM_DELETE,
	SMB_COM_DELETE_DIRECTORY,
	SMB_COM_FLUSH,
	SMB_COM_GET_PRINT_QUEUE,
	SMB_COM_LOCK_BYTE_RANGE,
	SMB_COM_NEGOTIATE,
	SMB_COM_OPEN,
	SMB_COM_OPEN_PRINT_FILE,
	SMB_COM_PROCESS_EXIT,
	SMB_COM_QUERY_INFORMATION,
	SMB_COM_QUERY_INFORMATION_DISK,
	SMB_COM_READ,
	SMB_COM_RENAME,
	SMB_COM_SEARCH,
	SMB_COM_SEEK,
	SMB_COM_SET_INFORMATION,
	SMB_COM_TREE_CONNECT,
	SMB_COM_TREE_DISCONNECT,
	SMB_COM_UNLOCK_BYTE_RANGE,
	SMB_COM_WRITE,
	SMB_COM_WRITE_PRINT_FILE
]

DIALECT['LANMAN 1.0'] = DIALECT['PC NETWORK PROGRAM 1.0'] + [
	SMB_COM_COPY,
	SMB_COM_ECHO,
	SMB_COM_FIND,
	SMB_COM_FIND_CLOSE,
	SMB_COM_FIND_UNIQUE,
	SMB_COM_IOCTL,
	SMB_COM_IOCTL_SECONDARY,
	SMB_COM_LOCK_AND_READ,
	SMB_COM_LOCKING_ANDX,
	SMB_COM_MOVE,
	SMB_COM_OPEN_ANDX,
	SMB_COM_QUERY_INFORMATION2,
	SMB_COM_READ_ANDX,
	SMB_COM_READ_MPX,
	SMB_COM_READ_RAW,
	SMB_COM_SESSION_SETUP_ANDX,
	SMB_COM_SET_INFORMATION2,
	SMB_COM_TRANSACTION,
	SMB_COM_TRANSACTION_SECONDARY,
	SMB_COM_TREE_CONNECT_ANDX,
	SMB_COM_WRITE_AND_CLOSE,
	SMB_COM_WRITE_AND_UNLOCK,
	SMB_COM_WRITE_ANDX,
	SMB_COM_WRITE_COMPLETE,
	SMB_COM_WRITE_MPX,
	SMB_COM_WRITE_MPX_SECONDARY,
	SMB_COM_WRITE_RAW
]

DIALECT['LM1.2X002'] = DIALECT['LANMAN 1.0'] + [
	SMB_COM_FIND_CLOSE2,
	SMB_COM_LOGOFF_ANDX,
	SMB_COM_TRANSACTION2,
	SMB_COM_TRANSACTION2_SECONDARY
]

DIALECT['NTLM 0.12'] = DIALECT['LM1.2X002'] + [
	SMB_COM_NT_CANCEL,
	SMB_COM_NT_CREATE_ANDX,
	SMB_COM_NT_RENAME,
	SMB_COM_NT_TRANSACT,
	SMB_COM_NT_TRANSACT_SECONDARY
]

# Create a NetBIOS session packet template
def self.make_nbs (template)
	Rex::Struct2::CStructTemplate.new(
		[ 'uint8',    'Type',             0 ],
		[ 'uint8',    'Flags',            0 ],
		[ 'uint16n',  'PayloadLen',       0 ],
		[ 'template', 'Payload',          template ]
	).create_restraints(
		[ 'Payload', 'PayloadLen',  nil, true ]
	)
end


# A raw NetBIOS session template
NBRAW_HDR_PKT =  Rex::Struct2::CStructTemplate.new(
	[ 'string', 'Payload', nil, '']
)
NBRAW_PKT = self.make_nbs(NBRAW_HDR_PKT)


# The SMB header template
SMB_HDR = Rex::Struct2::CStructTemplate.new(
	[ 'uint32n', 'Magic',             0xff534d42 ],
	[ 'uint8',   'Command',           0 ],
	[ 'uint32v', 'ErrorClass',        0 ],
	[ 'uint8',   'Flags1',            0 ],
	[ 'uint16v', 'Flags2',            0 ],
	[ 'uint16v', 'ProcessIDHigh',     0 ],
	[ 'uint32v', 'Signature1',        0 ],
	[ 'uint32v', 'Signature2',        0 ],
	[ 'uint16v', 'Reserved1',         0 ],
	[ 'uint16v', 'TreeID',            0 ],
	[ 'uint16v', 'ProcessID',         0 ],
	[ 'uint16v', 'UserID',            0 ],
	[ 'uint16v', 'MultiplexID',       0 ],
	[ 'uint8',   'WordCount',         0 ]
)


# The SMB2 header template
SMB2_HDR = Rex::Struct2::CStructTemplate.new(
	[ 'uint32n', 'Magic',             0xfe534d42 ],
	[ 'uint16v', 'HeaderLen',         64 ],
	[ 'uint16v', 'Reserved0',         0 ],
	[ 'uint32v', 'NTStatus',          0 ],

	[ 'uint16v', 'Opcode',            0 ],
	[ 'uint16v', 'Reserved1',         0 ],

	[ 'uint16v', 'Flags1',            0 ],
	[ 'uint16v', 'Flags2',            0 ],

	[ 'uint32v', 'ChainOffset',       0 ],

	[ 'uint32v', 'SequenceHigh',      0 ],
	[ 'uint32v', 'SequenceLow',       0 ],

	[ 'uint32v', 'ProcessID',         0 ],
	[ 'uint32v', 'TreeID',            0 ],
	[ 'uint32v', 'UserIDHigh',        0 ],
	[ 'uint32v', 'UserIDLow',         0 ],

	[ 'uint32v', 'SignatureA',        0 ],
	[ 'uint32v', 'SignatureB',        0 ],
	[ 'uint32v', 'SignatureC',        0 ],
	[ 'uint32v', 'SignatureD',        0 ],
	[ 'string',  'Payload', nil,      '']
)

# A basic SMB template to read all responses
SMB_BASE_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_BASE_PKT = self.make_nbs(SMB_BASE_HDR_PKT)


# A SMB template for SMB Dialect negotiation
SMB_NEG_HDR_PKT = Rex::Struct2::CStructTemplate.new(

	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_NEG_PKT = self.make_nbs(SMB_NEG_HDR_PKT)


# A SMB template for SMB Dialect negotiation responses (LANMAN)
SMB_NEG_RES_LM_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'Dialect',              0 ],
	[ 'uint16v', 'SecurityMode',         0 ],
	[ 'uint16v', 'MaxBuff',              0 ],
	[ 'uint16v', 'MaxMPX',               0 ],
	[ 'uint16v', 'MaxVCS',               0 ],
	[ 'uint16v', 'RawMode',              0 ],
	[ 'uint32v', 'SessionKey',           0 ],
	[ 'uint16v', 'DosTime',              0 ],
	[ 'uint16v', 'DosDate',              0 ],
	[ 'uint16v', 'Timezone',             0 ],
	[ 'uint16v', 'KeyLength',            0 ],
	[ 'uint16v', 'Reserved1',            0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'EncryptionKey', nil,  '' ]
).create_restraints(
	[ 'EncryptionKey', 'ByteCount',  nil, true ]
)
SMB_NEG_RES_LM_PKT = self.make_nbs(SMB_NEG_RES_LM_HDR_PKT)


# A SMB template for SMB Dialect negotiation responses (NTLM)
SMB_NEG_RES_NT_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'Dialect',              0 ],
	[ 'uint8',   'SecurityMode',         0 ],
	[ 'uint16v', 'MaxMPX',               0 ],
	[ 'uint16v', 'MaxVCS',               0 ],
	[ 'uint32v', 'MaxBuff',              0 ],
	[ 'uint32v', 'MaxRaw',               0 ],
	[ 'uint32v', 'SessionKey',           0 ],
	[ 'uint32v', 'Capabilities',         0 ],
	[ 'uint32v', 'SystemTimeLow',        0 ],
	[ 'uint32v', 'SystemTimeHigh',       0 ],
	[ 'uint16v', 'ServerTimeZone',       0 ],
	[ 'uint8',   'KeyLength',            0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_NEG_RES_NT_PKT = self.make_nbs(SMB_NEG_RES_NT_HDR_PKT)


# A SMB template for SMB Dialect negotiation responses (ERROR)
SMB_NEG_RES_ERR_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'Dialect',              0 ],
	[ 'uint16v', 'ByteCount',            0 ]
)
SMB_NEG_RES_ERR_PKT = self.make_nbs(SMB_NEG_RES_ERR_HDR_PKT)


# A SMB template for SMB Session Setup responses (LANMAN/NTLMV1)
SMB_SETUP_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'Action',               0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_RES_PKT = self.make_nbs(SMB_SETUP_RES_HDR_PKT)


# A SMB template for SMB Session Setup requests (LANMAN)
SMB_SETUP_LANMAN_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'MaxBuff',              0 ],
	[ 'uint16v', 'MaxMPX',               0 ],
	[ 'uint16v', 'VCNum',                0 ],
	[ 'uint32v', 'SessionKey',           0 ],
	[ 'uint16v', 'PasswordLen',          0 ],
	[ 'uint32v', 'Reserved2',            0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_LANMAN_PKT = self.make_nbs(SMB_SETUP_LANMAN_HDR_PKT)


# A SMB template for SMB Session Setup requests (NTLMV1)
SMB_SETUP_NTLMV1_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'MaxBuff',              0 ],
	[ 'uint16v', 'MaxMPX',               0 ],
	[ 'uint16v', 'VCNum',                0 ],
	[ 'uint32v', 'SessionKey',           0 ],
	[ 'uint16v', 'PasswordLenLM',        0 ],
	[ 'uint16v', 'PasswordLenNT',        0 ],
	[ 'uint32v', 'Reserved2',            0 ],
	[ 'uint32v', 'Capabilities',         0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_NTLMV1_PKT = self.make_nbs(SMB_SETUP_NTLMV1_HDR_PKT)


# A SMB template for SMB Session Setup requests (When extended security is being used)
SMB_SETUP_NTLMV2_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'MaxBuff',              0 ],
	[ 'uint16v', 'MaxMPX',               0 ],
	[ 'uint16v', 'VCNum',                0 ],
	[ 'uint32v', 'SessionKey',           0 ],
	[ 'uint16v', 'SecurityBlobLen',      0 ],
	[ 'uint32v', 'Reserved2',            0 ],
	[ 'uint32v', 'Capabilities',         0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_NTLMV2_PKT = self.make_nbs(SMB_SETUP_NTLMV2_HDR_PKT)


# A SMB template for SMB Session Setup responses (When extended security is being used)
SMB_SETUP_NTLMV2_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'Action',               0 ],
	[ 'uint16v', 'SecurityBlobLen',      0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_NTLMV2_RES_PKT = self.make_nbs(SMB_SETUP_NTLMV2_RES_HDR_PKT)


# A SMB template for SMB Tree Connect requests
SMB_TREE_CONN_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'Flags',                0 ],
	[ 'uint16v', 'PasswordLen',          0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_TREE_CONN_PKT = self.make_nbs(SMB_TREE_CONN_HDR_PKT)


# A SMB template for SMB Tree Connect requests
SMB_TREE_CONN_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],
	[ 'uint16v', 'OptionalSupport',      0 ],
	[ 'string',  'SupportWords', nil,   '' ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_TREE_CONN_RES_PKT = self.make_nbs(SMB_TREE_CONN_RES_HDR_PKT)


# A SMB template for SMB Tree Disconnect requests
SMB_TREE_DISCONN_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_TREE_DISCONN_PKT = self.make_nbs(SMB_TREE_DISCONN_HDR_PKT)


# A SMB template for SMB Tree Disconnect requests
SMB_TREE_DISCONN_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_TREE_DISCONN_RES_PKT = self.make_nbs(SMB_TREE_DISCONN_RES_HDR_PKT)


# A SMB template for SMB Transaction requests
SMB_TRANS_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'ParamCountTotal',     0 ],
	[ 'uint16v',  'DataCountTotal',      0 ],
	[ 'uint16v',  'ParamCountMax',       0 ],
	[ 'uint16v',  'DataCountMax',        0 ],
	[ 'uint8',    'SetupCountMax',       0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'Flags',               0 ],
	[ 'uint32v',  'Timeout',             0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint16v',  'ParamCount',          0 ],
	[ 'uint16v',  'ParamOffset',         0 ],
	[ 'uint16v',  'DataCount',           0 ],
	[ 'uint16v',  'DataOffset',          0 ],
	[ 'uint8',    'SetupCount',          0 ],
	[ 'uint8',    'Reserved3',           0 ],
	[ 'string',   'SetupData', nil,     '' ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_TRANS_PKT = self.make_nbs(SMB_TRANS_HDR_PKT)


# A SMB template for SMB Transaction responses
SMB_TRANS_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'ParamCountTotal',     0 ],
	[ 'uint16v',  'DataCountTotal',      0 ],
	[ 'uint16v',  'Reserved1',           0 ],
	[ 'uint16v',  'ParamCount',          0 ],
	[ 'uint16v',  'ParamOffset',         0 ],
	[ 'uint16v',  'ParamDisplace',       0 ],
	[ 'uint16v',  'DataCount',           0 ],
	[ 'uint16v',  'DataOffset',          0 ],
	[ 'uint16v',  'DataDisplace',        0 ],
	[ 'uint8',    'SetupCount',          0 ],
	[ 'uint8',    'Reserved2',           0 ],
	[ 'string',   'SetupData', nil,     '' ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_TRANS_RES_PKT = self.make_nbs(SMB_TRANS_RES_HDR_PKT)

# A SMB template for SMB Transaction2 requests
SMB_TRANS2_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'ParamCountTotal',     0 ],
	[ 'uint16v',  'DataCountTotal',      0 ],
	[ 'uint16v',  'ParamCountMax',       0 ],
	[ 'uint16v',  'DataCountMax',        0 ],
	[ 'uint8',    'SetupCountMax',       0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'Flags',               0 ],
	[ 'uint32v',  'Timeout',             0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint16v',  'ParamCount',          0 ],
	[ 'uint16v',  'ParamOffset',         0 ],
	[ 'uint16v',  'DataCount',           0 ],
	[ 'uint16v',  'DataOffset',          0 ],
	[ 'uint8',    'SetupCount',          0 ],
	[ 'uint8',    'Reserved3',           0 ],
	[ 'string',   'SetupData', nil,     '' ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_TRANS2_PKT = self.make_nbs(SMB_TRANS2_HDR_PKT)


# A SMB template for SMB NTTransaction requests
SMB_NTTRANS_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'SetupCountMax',       0 ],
	[ 'uint16v',  'Reserved1',           0 ],
	[ 'uint32v',  'ParamCountTotal',     0 ],
	[ 'uint32v',  'DataCountTotal',      0 ],
	[ 'uint32v',  'ParamCountMax',       0 ],
	[ 'uint32v',  'DataCountMax',        0 ],
	[ 'uint32v',  'ParamCount',          0 ],
	[ 'uint32v',  'ParamOffset',         0 ],
	[ 'uint32v',  'DataCount',           0 ],
	[ 'uint32v',  'DataOffset',          0 ],
	[ 'uint8',    'SetupCount',          0 ],
	[ 'uint16v',  'Subcommand',          0 ],
	[ 'string',   'SetupData', nil,     '' ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_NTTRANS_PKT = self.make_nbs(SMB_NTTRANS_HDR_PKT)


# A SMB template for SMB NTTransaction responses
SMB_NTTRANS_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint32v',  'ParamCountTotal',     0 ],
	[ 'uint32v',  'DataCountTotal',      0 ],
	[ 'uint32v',  'ParamCount',          0 ],
	[ 'uint32v',  'ParamOffset',         0 ],
	[ 'uint32v',  'ParamDisplace',       0 ],
	[ 'uint32v',  'DataCount',           0 ],
	[ 'uint32v',  'DataOffset',          0 ],
	[ 'uint32v',  'DataDisplace',        0 ],
	[ 'uint8',    'Reserved3',           0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_NTTRANS_RES_PKT = self.make_nbs(SMB_NTTRANS_RES_HDR_PKT)

# A SMB template for SMB NTTransaction_Secondary requests
SMB_NTTRANS_SECONDARY_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint32v',  'ParamCountTotal',     0 ],
	[ 'uint32v',  'DataCountTotal',      0 ],
	[ 'uint32v',  'ParamCount',          0 ],
	[ 'uint32v',  'ParamOffset',         0 ],
	[ 'uint32v',  'ParamDisplace',       0 ],
	[ 'uint32v',  'DataCount',           0 ],
	[ 'uint32v',  'DataOffset',          0 ],
	[ 'uint32v',  'DataDisplace',        0 ],
	[ 'uint8',    'SetupCount',          0 ],
	[ 'string',   'SetupData', nil,     '' ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_NTTRANS_SECONDARY_PKT = self.make_nbs(SMB_NTTRANS_SECONDARY_HDR_PKT)

# A SMB template for SMB Create requests
SMB_CREATE_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint8',    'Reserved2',           0 ],
	[ 'uint16v',  'FileNameLen',         0 ],
	[ 'uint32v',  'CreateFlags',         0 ],
	[ 'uint32v',  'RootFileID',          0 ],
	[ 'uint32v',  'AccessMask',          0 ],
	[ 'uint32v',  'AllocLow',            0 ],
	[ 'uint32v',  'AllocHigh',           0 ],
	[ 'uint32v',  'Attributes',          0 ],
	[ 'uint32v',  'ShareAccess',         0 ],
	[ 'uint32v',  'Disposition',         0 ],
	[ 'uint32v',  'CreateOptions',       0 ],
	[ 'uint32v',  'Impersonation',       0 ],
	[ 'uint8',    'SecurityFlags',       0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_CREATE_PKT = self.make_nbs(SMB_CREATE_HDR_PKT)


# A SMB template for SMB Create responses
SMB_CREATE_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint8',    'OpLock',              0 ],
	[ 'uint16v',  'FileID',              0 ],
	[ 'uint32v',  'Action',              0 ],
	[ 'uint32v',  'CreateTimeLow',       0 ],
	[ 'uint32v',  'CreateTimeHigh',      0 ],
	[ 'uint32v',  'AccessTimeLow',       0 ],
	[ 'uint32v',  'AccessTimeHigh',      0 ],
	[ 'uint32v',  'WriteTimeLow',        0 ],
	[ 'uint32v',  'WriteTimeHigh',       0 ],
	[ 'uint32v',  'ChangeTimeLow',       0 ],
	[ 'uint32v',  'ChangeTimeHigh',      0 ],
	[ 'uint32v',  'Attributes',          0 ],
	[ 'uint32v',  'AllocLow',            0 ],
	[ 'uint32v',  'AllocHigh',           0 ],
	[ 'uint32v',  'EOFLow',              0 ],
	[ 'uint32v',  'EOFHigh',             0 ],
	[ 'uint16v',  'FileType',            0 ],
	[ 'uint16v',  'IPCState',            0 ],
	[ 'uint8',    'IsDirectory',         0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_CREATE_RES_PKT = self.make_nbs(SMB_CREATE_RES_HDR_PKT)


# A SMB template for SMB Write requests
SMB_WRITE_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint16v',  'FileID',              0 ],
	[ 'uint32v',  'Offset',              0 ],
	[ 'uint32v',  'Reserved2',           0 ],
	[ 'uint16v',  'WriteMode',           0 ],
	[ 'uint16v',  'Remaining',           0 ],
	[ 'uint16v',  'DataLenHigh',         0 ],
	[ 'uint16v',  'DataLenLow',          0 ],
	[ 'uint16v',  'DataOffset',          0 ],
	[ 'uint32v',  'DataOffsetHigh',      0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_WRITE_PKT = self.make_nbs(SMB_WRITE_HDR_PKT)


# A SMB template for SMB Write responses
SMB_WRITE_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint16v',  'CountLow',            0 ],
	[ 'uint16v',  'Remaining',           0 ],
	[ 'uint16v',  'CountHigh',           0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_WRITE_RES_PKT = self.make_nbs(SMB_WRITE_RES_HDR_PKT)


# A SMB template for SMB OPEN requests
SMB_OPEN_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint16v',  'Flags',               0 ],
	[ 'uint16v',  'Access',              0 ],
	[ 'uint16v',  'SearchAttributes',    0 ],
	[ 'uint16v',  'FileAttributes',      0 ],
	[ 'uint32v',  'CreateTime',          0 ],
	[ 'uint16v',  'OpenFunction',        0 ],
	[ 'uint32v',  'AllocSize',           0 ],
	[ 'uint32v',  'Reserved2',           0 ],
	[ 'uint32v',  'Reserved3',           0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_OPEN_PKT = self.make_nbs(SMB_OPEN_HDR_PKT)


# A SMB template for SMB OPEN responses
SMB_OPEN_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint16v',  'FileID',              0 ],
	[ 'uint16v',  'FileAttributes',      0 ],
	[ 'uint32v',  'WriteTime',           0 ],
	[ 'uint32v',  'FileSize',            0 ],
	[ 'uint16v',  'FileAccess',          0 ],
	[ 'uint16v',  'FileType',            0 ],
	[ 'uint16v',  'IPCState',            0 ],
	[ 'uint16v',  'Action',              0 ],
	[ 'uint32v',  'ServerFileID',        0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_OPEN_RES_PKT = self.make_nbs(SMB_OPEN_RES_HDR_PKT)


# A SMB template for SMB Close requests
SMB_CLOSE_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'FileID',              0 ],
	[ 'uint32v',  'LastWrite',           0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_CLOSE_PKT = self.make_nbs(SMB_CLOSE_HDR_PKT)


# A SMB template for SMB Close responses
SMB_CLOSE_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_CLOSE_RES_PKT = self.make_nbs(SMB_CLOSE_RES_HDR_PKT)


# A SMB template for SMB Delete requests
SMB_DELETE_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'SearchAttribute',     0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'uint8',    'BufferFormat',        0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_DELETE_PKT = self.make_nbs(SMB_DELETE_HDR_PKT)


# A SMB template for SMB Delete responses
SMB_DELETE_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_DELETE_RES_PKT = self.make_nbs(SMB_DELETE_RES_HDR_PKT)



# A SMB template for SMB Read requests
SMB_READ_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint16v',  'FileID',              0 ],
	[ 'uint32v',  'Offset',              0 ],
	[ 'uint16v',  'MaxCountLow',         0 ],
	[ 'uint16v',  'MinCount',            0 ],
	[ 'uint32v',  'Reserved2',           0 ],
	[ 'uint16v',  'Remaining',           0 ],
	[ 'uint32v',  'MaxCountHigh',        0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_READ_PKT = self.make_nbs(SMB_READ_HDR_PKT)


# A SMB template for SMB Read responses
SMB_READ_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',    'AndX',                0 ],
	[ 'uint8',    'Reserved1',           0 ],
	[ 'uint16v',  'AndXOffset',          0 ],
	[ 'uint16v',  'Remaining',           0 ],
	[ 'uint16v',  'DataCompaction',      0 ],
	[ 'uint16v',  'Reserved2',           0 ],
	[ 'uint16v',  'DataLenLow',          0 ],
	[ 'uint16v',  'DataOffset',          0 ],
	[ 'uint32v',  'DataLenHigh',         0 ],
	[ 'uint32v',  'Reserved3',           0 ],
	[ 'uint16v',  'Reserved4',           0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_READ_RES_PKT = self.make_nbs(SMB_READ_RES_HDR_PKT)



# A SMB template for SMB Search requests
SMB_SEARCH_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v',  'MaxCount',            0 ],
	[ 'uint16v',  'Attributes',          0 ],
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_SEARCH_PKT = self.make_nbs(SMB_SEARCH_HDR_PKT)


end
end
end
end

