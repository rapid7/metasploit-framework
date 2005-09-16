module Rex
module Proto
module SMB
class Constants

require 'rex/text'
require 'rex/struct2'

# SMB Commands
SMB_COM_CREATE_DIR          = 0x00
SMB_COM_DELETE_DIR          = 0x01
SMB_COM_CLOSE               = 0x04
SMB_COM_DELETE              = 0x06
SMB_COM_RENAME              = 0x07
SMB_COM_CHECK_DIR           = 0x10
SMB_COM_READ_RAW            = 0x1a
SMB_COM_WRITE_RAW           = 0x1d
SMB_COM_TRANSACTION         = 0x25
SMB_COM_TRANSACTION2        = 0x32
SMB_COM_OPEN_ANDX           = 0x2d
SMB_COM_READ_ANDX           = 0x2e
SMB_COM_WRITE_ANDX          = 0x2f
SMB_COM_TREE_DISCONNECT     = 0x71
SMB_COM_NEGOTIATE           = 0x72
SMB_COM_SESSION_SETUP_ANDX  = 0x73
SMB_COM_LOGOFF              = 0x74
SMB_COM_TREE_CONNECT_ANDX   = 0x75
SMB_COM_NT_TRANSACT         = 0xa0
SMB_COM_CREATE_ANDX         = 0xa2

# SMB_COM_NT_TRANSACT Subcommands
NT_TRANSACT_CREATE                   = 1 # File open/create
NT_TRANSACT_IOCTL                    = 2 # Device IOCTL
NT_TRANSACT_SET_SECURITY_DESC        = 3 # Set security descriptor
NT_TRANSACT_NOTIFY_CHANGE            = 4 # Start directory watch
NT_TRANSACT_RENAME                   = 5 # Reserved (Handle-based)
NT_TRANSACT_QUERY_SECURITY_DESC      = 6 # Retrieve security

# Wildcard NetBIOS name
NETBIOS_REDIR = 'CACACACACACACACACACACACACACACAAA'


# SMB Structures

NB_HDR = Rex::Struct2::CStructTemplate.new(
	[ 'uint8',   'Type',             0 ],
	[ 'uint8',   'Flags',            0 ],
	[ 'uint16n', 'RequestLen',       0 ],
	[ 'string',  'Request',         '' ]
)

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
	[ 'string',  'Request',          '' ]
)

NB_NEG_HDR = Rex::Struct2::CStructTemplate.new(
	[ 'uint8',   'WordCount',            0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Request',             '' ]
)

NB_NEG_RES_LM_HDR = Rex::Struct2::CStructTemplate.new(
	[ 'uint8',   'WordCount',            0 ],
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
	[ 'string',  'EncryptionKey',       '' ]
)

NB_NEG_RES_NT_HDR = Rex::Struct2::CStructTemplate.new(
	[ 'uint8',   'WordCount',            0 ],
	[ 'uint16v', 'Dialect',              0 ],
	[ 'uint8',   'SecurityMode',         0 ],
	[ 'uint16v', 'MaxMPX',               0 ],
	[ 'uint16v', 'MaxVCS',               0 ],
	[ 'uint32v', 'MaxBuff',              0 ],
	[ 'uint32v', 'MaxRaw',               0 ],		
	[ 'uint32v', 'SessionKey',           0 ],
	[ 'uint32v', 'Capabilities',         0 ],
	[ 'uint32v', 'DosTime',              0 ],
	[ 'uint32v', 'DosDate',              0 ],
	[ 'uint16v', 'Timezone',             0 ],
	[ 'uint8',   'KeyLength',            0 ],	
	[ 'uint16v', 'ByteCount',            0 ],		
	[ 'string',  'EncryptionKey',       '' ],
	[ 'string',  'Domain',              '' ],
	[ 'string',  'Server',              '' ]
)

end
end
end
end
