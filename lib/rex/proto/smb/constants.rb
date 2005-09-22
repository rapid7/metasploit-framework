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
	[ 'uint32v', 'DosTime',              0 ],
	[ 'uint32v', 'DosDate',              0 ],
	[ 'uint16v', 'Timezone',             0 ],
	[ 'uint8',   'KeyLength',            0 ],	
	[ 'uint16v', 'ByteCount',            0 ],		
	[ 'string',  'GUID', 16,            '' ],
	[ 'string',  'SecurityBlob', nil,   '' ]
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
	[ 'uint16v', 'SecurityBlobLen',      0 ],
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
	[ 'string',  'Payload', nil,        '' ]
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
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload', nil,        '' ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_TREE_CONN_RES_PKT = self.make_nbs(SMB_TREE_CONN_RES_HDR_PKT)


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
	[ 'uint16v',  'Reserved1',           0 ],

	[ 'uint16v',  'ParamCount',          0 ],
	[ 'uint16v',  'ParamOffset',         0 ],	
	[ 'uint16v',  'DataCount',           0 ],
	[ 'uint16v',  'DataOffset',          0 ],	
	[ 'uint8',    'SetupCount',          0 ],
	[ 'uint8',    'Reserved3',           0 ],
	[ 'string',   'SetupData', nil,     '' ], # SetupCount * 2			
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ],
	[ 'SetupData', 'SetupCount', nil, true, nil, nil, proc { |i| i * 2 }, nil ]	
)
SMB_TRANS_PKT = self.make_nbs(SMB_TRANS_HDR_PKT)


end
end
end
end
