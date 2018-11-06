module RubySMB
  module SMB2
    module Packet
      # An SMB2 Close Response Packet as defined in
      # [2.2.16 SMB2 CLOSE Response](https://msdn.microsoft.com/en-us/library/cc246524.aspx)
      class CloseResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::CLOSE

        endian :little

        smb2_header      :smb2_header
        uint16           :structure_size,   label: 'Structure Size', initial_value: 60
        uint16           :flags,            label: 'Flags'
        uint32           :reserved,         label: 'Reserved Space'
        file_time        :create_time,      label: 'Create Time'
        file_time        :last_access,      label: 'Last Accessed Time'
        file_time        :last_write,       label: 'Last Write Time'
        file_time        :last_change,      label: 'Last Modified Time'
        uint64           :allocation_size,  label: 'Allocated Size'
        uint64           :end_of_file,      label: 'End of File'
        file_attributes  :file_attributes,  label: 'File Attributes'

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
