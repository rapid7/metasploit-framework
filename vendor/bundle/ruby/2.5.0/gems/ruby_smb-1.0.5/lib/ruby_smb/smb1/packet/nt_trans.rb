module RubySMB
  module SMB1
    module Packet
      # Namespace for the NT Transaction sub-protocol documented in
      # [2.2.4.62 SMB_COM_NT_TRANSACT (0xA0)](https://msdn.microsoft.com/en-us/library/ee441720.aspx)
      module NtTrans
        require 'ruby_smb/smb1/packet/nt_trans/subcommands'
        require 'ruby_smb/smb1/packet/nt_trans/request'
        require 'ruby_smb/smb1/packet/nt_trans/response'
        require 'ruby_smb/smb1/packet/nt_trans/create_request'
        require 'ruby_smb/smb1/packet/nt_trans/create_response'
      end
    end
  end
end
