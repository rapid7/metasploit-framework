module RubySMB
  module SMB2
    module Packet
      # An SMB2 Ioctl Request Packet as defined in
      # [2.2.31 SMB2 IOCTL Request](https://msdn.microsoft.com/en-us/library/cc246545.aspx)
      class IoctlRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::IOCTL

        endian :little

        smb2_header   :smb2_header
        uint16        :structure_size,      label: 'Structure Size',      initial_value: 57
        uint16        :reserved1,           label: 'Reserved Space'
        uint32        :ctl_code,            label: 'Control Code'
        smb2_fileid   :file_id,             label: 'File Id'
        uint32        :input_offset,        label: 'Input Offset',        initial_value: -> { calc_input_offset }
        uint32        :input_count,         label: 'Input Count',         initial_value: -> { buffer.do_num_bytes }
        uint32        :max_input_response,  label: 'Max Input Response'
        uint32        :output_offset,       label: 'Output Offset',       initial_value: -> { input_offset + output_count }
        uint32        :output_count,        label: 'Output Count'
        uint32        :max_output_response, label: 'Max Output response', initial_value: 1024

        struct :flags do
          bit7  :reserved1, label: 'Reserved Space'
          bit1  :is_fsctl,  label: 'FSCTL not IOCTL'

          bit8  :reserved2, label: 'Reserved Space'
          bit8  :reserved3, label: 'Reserved Space'
          bit8  :reserved4, label: 'Reserved Space'
        end

        uint32  :reserved2, label: 'Reserved Space'
        string  :buffer,    label: 'Input Buffer', read_length: -> { input_count + output_count }

        # Calculates the value for the input_offset field.
        # If the input buffer is empty then this should be set to 0,
        # otherwise it should return the absolute offset of the input buffer.
        #
        # @return [Integer] the value to store in #input_offset
        def calc_input_offset
          if input_count.zero?
            0
          else
            buffer.abs_offset
          end
        end

      end
    end
  end
end
