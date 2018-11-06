module RubySMB
  module SMB1
    # Namespace for all SMB1 packet definitions
    # see [2.2 Message Syntax](https://msdn.microsoft.com/en-us/library/ee441466.aspx)
    module Packet
      require 'ruby_smb/smb1/packet/empty_packet'
      require 'ruby_smb/smb1/packet/negotiate_request'
      require 'ruby_smb/smb1/packet/negotiate_response'
      require 'ruby_smb/smb1/packet/negotiate_response_extended'
      require 'ruby_smb/smb1/packet/session_setup_request'
      require 'ruby_smb/smb1/packet/session_setup_legacy_request'
      require 'ruby_smb/smb1/packet/session_setup_response'
      require 'ruby_smb/smb1/packet/session_setup_legacy_response'
      require 'ruby_smb/smb1/packet/tree_connect_request'
      require 'ruby_smb/smb1/packet/tree_connect_response'
      require 'ruby_smb/smb1/packet/tree_disconnect_request'
      require 'ruby_smb/smb1/packet/tree_disconnect_response'
      require 'ruby_smb/smb1/packet/logoff_request'
      require 'ruby_smb/smb1/packet/logoff_response'
      require 'ruby_smb/smb1/packet/echo_request'
      require 'ruby_smb/smb1/packet/echo_response'
      require 'ruby_smb/smb1/packet/trans'
      require 'ruby_smb/smb1/packet/trans2'
      require 'ruby_smb/smb1/packet/nt_trans'
      require 'ruby_smb/smb1/packet/nt_create_andx_request'
      require 'ruby_smb/smb1/packet/nt_create_andx_response'
      require 'ruby_smb/smb1/packet/read_andx_request'
      require 'ruby_smb/smb1/packet/read_andx_response'
      require 'ruby_smb/smb1/packet/write_andx_request'
      require 'ruby_smb/smb1/packet/write_andx_response'
      require 'ruby_smb/smb1/packet/close_request'
      require 'ruby_smb/smb1/packet/close_response'
      require 'ruby_smb/smb1/packet/trans'
    end
  end
end
