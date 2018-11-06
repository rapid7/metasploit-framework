module RubySMB
  # A packet parsing and manipulation library for the SMB2 protocol
  #
  # [[MS-SMB2] Server Mesage Block (SMB) Protocol Versions 2 and 3](https://msdn.microsoft.com/en-us/library/cc246482.aspx)
  module SMB2
    # Protocol ID value. Translates to \xFESMB
    SMB2_PROTOCOL_ID = 0xFE534D42

    require 'ruby_smb/smb2/info_type'
    require 'ruby_smb/smb2/commands'
    require 'ruby_smb/smb2/create_context'
    require 'ruby_smb/smb2/bit_field'
    require 'ruby_smb/smb2/smb2_header'
    require 'ruby_smb/smb2/packet'
    require 'ruby_smb/smb2/tree'
    require 'ruby_smb/smb2/file'
    require 'ruby_smb/smb2/pipe'
  end
end
