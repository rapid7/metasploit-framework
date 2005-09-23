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
	[ 'uint16v',  'ParamDisp',           0 ],
	[ 'uint16v',  'DataCount',           0 ],
	[ 'uint16v',  'DataOffset',          0 ],
	[ 'uint16v',  'DataDisp',            0 ],		
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
	[ 'uint16v',  'Subcommand',          0 ],	
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
	[ 'string',   'SetupData', nil,     '' ],
	[ 'uint16v',  'Subcommand',          0 ],	
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_NTTRANS_PKT = self.make_nbs(SMB_NTTRANS_HDR_PKT)


# A SMB template for SMB NTTransaction responses
SMB_NTTRANS_RES_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint32v',  'ParamCountTotal',     0 ],
	[ 'uint32v',  'DataCountTotal',      0 ],
	[ 'uint32v',  'Reserved1',           0 ],		
	[ 'uint32v',  'ParamCount',          0 ],
	[ 'uint32v',  'ParamOffset',         0 ],
	[ 'uint32v',  'ParamDisp',           0 ],		
	[ 'uint32v',  'DataCount',           0 ],
	[ 'uint32v',  'DataOffset',          0 ],
	[ 'uint32v',  'DataDisp',            0 ],
	[ 'uint8',    'SetupCount',          0 ],
	[ 'uint8',    'Reserved2',           0 ],
	[ 'string',   'SetupData', nil,     '' ],	
	[ 'uint16v',  'ByteCount',           0 ],
	[ 'string',   'Payload', nil,       '' ]
).create_restraints(
	[ 'Payload',   'ByteCount',  nil, true ]
)
SMB_NTTRANS_RES_PKT = self.make_nbs(SMB_NTTRANS_RES_HDR_PKT)


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
	[ 'uint32v',  'MaxCountHigh',        0 ],
	[ 'uint16v',  'Remaining',           0 ],
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

end
end
end
end
