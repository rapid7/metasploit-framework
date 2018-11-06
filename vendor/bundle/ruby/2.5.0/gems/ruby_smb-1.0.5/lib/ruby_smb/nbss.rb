module RubySMB
  # Namespace for all of the NetBIOS packets used by RubySMB
  module Nbss
    # Session Packet Types
    SESSION_MESSAGE           = 0x00
    SESSION_REQUEST           = 0x81
    POSITIVE_SESSION_RESPONSE = 0x82
    NEGATIVE_SESSION_RESPONSE = 0x83
    RETARGET_SESSION_RESPONSE = 0x84
    SESSION_KEEP_ALIVE        = 0x85

    require 'ruby_smb/nbss/netbios_name'
    require 'ruby_smb/nbss/session_header'
    require 'ruby_smb/nbss/session_request'
    require 'ruby_smb/nbss/negative_session_response'
  end
end
