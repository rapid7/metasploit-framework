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
	[ 'string', 'Payload'               ]
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


# A basic SMB template to read all responses
SMB_BASE_HDR_PKT = Rex::Struct2::CStructTemplate.new(

	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'string',  'Payload'                 ]
)
SMB_BASE_PKT = self.make_nbs(SMB_BASE_HDR_PKT)


# A SMB template for SMB Dialect negotiation
SMB_NEG_HDR_PKT = Rex::Struct2::CStructTemplate.new(

	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload'                 ]
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
	[ 'string',  'EncryptionKey'           ]
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
	[ 'uint32v', 'DosTime',              0 ],
	[ 'uint32v', 'DosDate',              0 ],
	[ 'uint16v', 'Timezone',             0 ],
	[ 'uint8',   'KeyLength',            0 ],	
	[ 'uint16v', 'ByteCount',            0 ],		
	[ 'string',  'GUID', 16,            '' ],
	[ 'string',  'SecurityBlob'            ]
)
SMB_NEG_RES_NT_PKT = self.make_nbs(SMB_NEG_RES_NT_HDR_PKT)


# A SMB template for SMB Dialect negotiation responses (ERROR)
SMB_NEG_RES_ERR_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint16v', 'Dialect',              0 ],
	[ 'uint16v', 'ByteCount',            0 ]	
)
SMB_NEG_RES_ERR_PKT = self.make_nbs(SMB_NEG_RES_ERR_HDR_PKT)


# A SMB template for SMB Session Setup requests (NTLMV2)
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
	[ 'string',  'Payload'                 ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_NTLMV2_PKT = self.make_nbs(SMB_SETUP_NTLMV2_HDR_PKT)

# A SMB template for SMB Session Setup responses (NTLMV2)
SMB_SETUP_NTLMV2_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],			
	[ 'uint16v', 'Action',               0 ],
	[ 'uint16v', 'SecurityBlobLen',      0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload'                 ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_SETUP_NTLMV2_RES_PKT = self.make_nbs(SMB_SETUP_NTLMV2_RES_HDR_PKT)

end
end
end
end
