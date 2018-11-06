module RubySMB
  module SMB2
    module Packet
      # An SMB2 NEGOTIATE Response packet as defined by
      # [2.2.4 SMB2 NEGOTIATE Response](https://msdn.microsoft.com/en-us/library/cc246561.aspx)
      class NegotiateResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::NEGOTIATE

        endian              :little
        smb2_header         :smb2_header
        uint16              :structure_size, label: 'Structure Size', initial_value: 65
        smb2_security_mode  :security_mode
        uint16              :dialect_revision,          label: 'Dialect Revision'
        uint16              :negotiate_context_count,   label: 'Negotiate Context Count',      initial_value: 0
        string              :server_guid,               label: 'Server GUID',                  length: 16
        smb2_capabilities   :capabilities
        uint32              :max_transact_size,         label: 'Max Transaction Size'
        uint32              :max_read_size,             label: 'Max Read Size'
        uint32              :max_write_size,            label: 'Max Write Size'
        file_time           :system_time,               label: 'Server System Time'
        file_time           :server_start_time,         label: 'Server Start Time'
        uint16              :security_buffer_offset,    label: 'Offset to Security Buffer'
        uint16              :security_buffer_length,    label: 'Security Buffer Length', initial_value: -> { security_buffer.length }
        uint32              :negotiate_context_offset,  label: 'Offset to Negotiate Context'
        string              :security_buffer,           label: 'Security Buffer', read_length: :security_buffer_length

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
