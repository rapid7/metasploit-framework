module RubySMB
  module SMB2
    module Packet
      # An SMB2 Ioctl Response Packet as defined in
      # [2.2.32 SMB2 IOCTL Response](https://msdn.microsoft.com/en-us/library/cc246548.aspx)
      class IoctlResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::IOCTL

        endian :little

        smb2_header   :smb2_header
        uint16        :structure_size,      label: 'Structure Size',      initial_value: 49
        uint16        :reserved1,           label: 'Reserved Space'
        uint32        :ctl_code,            label: 'Control Code'
        smb2_fileid   :file_id,             label: 'File Id'
        uint32        :input_offset,        label: 'Input Offset'
        uint32        :input_count,         label: 'Input Count'
        uint32        :output_offset,       label: 'Output Offset'
        uint32        :output_count,        label: 'Output Count'
        uint32        :flags,               label: 'Flags'
        uint32        :reserved2,           label: 'Reserved Space'
        string        :buffer,              label: 'Input Buffer',        read_length: -> { input_count + output_count }

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end

        def input_data
          to_binary_s[input_offset, input_count]
        end

        def output_data
          to_binary_s[output_offset, output_count]
        end

      end
    end
  end
end
