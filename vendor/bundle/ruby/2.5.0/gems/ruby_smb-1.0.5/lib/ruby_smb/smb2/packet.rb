module RubySMB
  module SMB2
    # Namespace for all of the packet definitions for SMB2
    # see [2.2 Message Syntax](https://msdn.microsoft.com/en-us/library/cc246497.aspx)
    module Packet
      require 'ruby_smb/smb2/packet/error_packet'
      require 'ruby_smb/smb2/packet/negotiate_request'
      require 'ruby_smb/smb2/packet/negotiate_response'
      require 'ruby_smb/smb2/packet/session_setup_request'
      require 'ruby_smb/smb2/packet/session_setup_response'
      require 'ruby_smb/smb2/packet/tree_connect_request'
      require 'ruby_smb/smb2/packet/tree_connect_response'
      require 'ruby_smb/smb2/packet/tree_disconnect_request'
      require 'ruby_smb/smb2/packet/tree_disconnect_response'
      require 'ruby_smb/smb2/packet/logoff_request'
      require 'ruby_smb/smb2/packet/logoff_response'
      require 'ruby_smb/smb2/packet/echo_request'
      require 'ruby_smb/smb2/packet/echo_response'
      require 'ruby_smb/smb2/packet/create_request'
      require 'ruby_smb/smb2/packet/create_response'
      require 'ruby_smb/smb2/packet/query_directory_request'
      require 'ruby_smb/smb2/packet/query_directory_response'
      require 'ruby_smb/smb2/packet/read_request'
      require 'ruby_smb/smb2/packet/read_response'
      require 'ruby_smb/smb2/packet/set_info_request'
      require 'ruby_smb/smb2/packet/set_info_response'
      require 'ruby_smb/smb2/packet/close_request'
      require 'ruby_smb/smb2/packet/close_response'
      require 'ruby_smb/smb2/packet/write_request'
      require 'ruby_smb/smb2/packet/write_response'
      require 'ruby_smb/smb2/packet/ioctl_request'
      require 'ruby_smb/smb2/packet/ioctl_response'
    end
  end
end
