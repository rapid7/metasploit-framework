module RubySMB
  module SMB2
    module Packet
      # An SMB2 SessionSetupRequest Packet as defined in
      # [2.2.5 SMB2 SESSION_SETUP Request](https://msdn.microsoft.com/en-us/library/cc246563.aspx)
      class SessionSetupRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::SESSION_SETUP

        endian                     :little
        smb2_header                :smb2_header
        uint16                     :structure_size,          label: 'Structure Size',          initial_value: 25
        uint8                      :flags,                   label: 'Flags',                   initial_value: 0x00
        smb2_security_mode_single  :security_mode
        smb2_capabilities          :capabilities
        uint32                     :channel,                 label: 'Channel',                 initial_value: 0x00
        uint16                     :security_buffer_offset,  label: 'Security Buffer Offset',  initial_value: 0x58
        uint16                     :security_buffer_length,  label: 'Security Buffer Length'
        uint64                     :previous_session_id,     label: 'Previous Session ID'
        string                     :buffer,                  label: 'Security Buffer', length: -> { security_buffer_length }

        # Takes a serialized NTLM Type 1 message and wraps it in the GSS ASN1 encoding
        # and inserts it into the {RubySMB::SMB2::Packet::SessionSetupRequest#buffer}
        # as well as updating the {RubySMB::SMB2::Packet::SessionSetupRequest#security_buffer_length}
        #
        # @param type1_message [String] the serialized NTLM Type 1 message
        # @return [void]
        def set_type1_blob(type1_message)
          gss_blob = RubySMB::Gss.gss_type1(type1_message)
          self.security_buffer_length = gss_blob.length
          self.buffer = gss_blob
        end

        # Takes a serialized NTLM Type 3 message and wraps it in the GSS ASN1 encoding
        # and inserts it into the {RubySMB::SMB2::Packet::SessionSetupRequest#buffer}
        # as well as updating the {RubySMB::SMB2::Packet::SessionSetupRequest#security_buffer_length}
        #
        # @param type3_message [String] the serialized NTLM Type 3 message
        # @return [void]
        def set_type3_blob(type3_message)
          gss_blob = RubySMB::Gss.gss_type3(type3_message)
          self.security_buffer_length = gss_blob.length
          self.buffer = gss_blob
        end
      end
    end
  end
end
