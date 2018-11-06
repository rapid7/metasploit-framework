module RubySMB
  module SMB2
    module Packet
      # An SMB2 SessionSetupResponse Packet as defined in
      # [2.2.6 SMB2 SESSION_SETUP Response](https://msdn.microsoft.com/en-us/library/cc246564.aspx)
      class SessionSetupResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::SESSION_SETUP

        endian :little
        smb2_header         :smb2_header
        uint16              :structure_size, label: 'Structure Size', initial_value: 9
        session_flags       :session_flags
        uint16              :security_buffer_offset,  label: 'Security Buffer Offset', initial_value: 0x48
        uint16              :security_buffer_length,  label: 'Security Buffer Length'
        string              :buffer,                  label: 'Security Buffer', length: -> { security_buffer_length }

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end

        # Takes a serialized NTLM Type 2 message and wraps it in the GSS ASN1 encoding
        # and inserts it into the {RubySMB::SMB2::Packet::SessionSetupRequest#buffer}
        # as well as updating the {RubySMB::SMB2::Packet::SessionSetupRequest#security_buffer_length}
        #
        # @param type1_message [String] the serialized NTLM Type 1 message
        # @return [void]
        def set_type2_blob(type1_message)
          gss_blob = RubySMB::Gss.gss_type2(type1_message)
          self.security_buffer_length = gss_blob.length
          self.buffer = gss_blob
        end
      end
    end
  end
end
