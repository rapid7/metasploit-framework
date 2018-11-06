module RubySMB
  module SMB1
    module Packet
      # Namespace for the Transaction sub-protocol documented in
      # [2.2.4.33 SMB_COM_TRANSACTION (0x25)](https://msdn.microsoft.com/en-us/library/ee441489.aspx)
      module Trans
        MAX_PARAMETER_COUNT = 1024
        MAX_DATA_COUNT      = 1024
        MAX_SETUP_COUNT     = 255

        require 'ruby_smb/smb1/packet/trans/data_block'
        require 'ruby_smb/smb1/packet/trans/subcommands'
        require 'ruby_smb/smb1/packet/trans/request'
        require 'ruby_smb/smb1/packet/trans/response'
        require 'ruby_smb/smb1/packet/trans/transact_nmpipe_request'
        require 'ruby_smb/smb1/packet/trans/transact_nmpipe_response'
        require 'ruby_smb/smb1/packet/trans/peek_nmpipe_request'
        require 'ruby_smb/smb1/packet/trans/peek_nmpipe_response'
      end
    end
  end
end
