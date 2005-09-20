$:.unshift(File.join(File.dirname(__FILE__), '../../lib'))

require 'rex/struct2'

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

# A SMB template for SMB Tree Connect requests
SMB_TREE_CONN_HDR_PKT = Rex::Struct2::CStructTemplate.new(
	[ 'template', 'SMB',                 SMB_HDR ],
	[ 'uint8',   'AndX',                 0 ],
	[ 'uint8',   'Reserved1',            0 ],
	[ 'uint16v', 'AndXOffset',           0 ],			
	[ 'uint16v', 'Flags',                0 ],
	[ 'uint16v', 'PasswordLen',          0 ],
	[ 'uint16v', 'ByteCount',            0 ],
	[ 'string',  'Payload'                 ]
).create_restraints(
	[ 'Payload', 'ByteCount',  nil, true ]
)
SMB_TREE_CONN_PKT = self.make_nbs(SMB_TREE_CONN_HDR_PKT)


x = SMB_TREE_CONN_PKT.make_struct
p x.to_s
