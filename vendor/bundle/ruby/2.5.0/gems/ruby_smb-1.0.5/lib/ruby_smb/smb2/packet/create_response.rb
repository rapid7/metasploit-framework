module RubySMB
  module SMB2
    module Packet
      # An SMB2 Create Response Packet as defined in
      # [2.2.14 SMB2 CREATE Response](https://msdn.microsoft.com/en-us/library/cc246512.aspx)
      class CreateResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::CREATE

        endian :little
        smb2_header           :smb2_header
        uint16                :structure_size,       label: 'Structure Size', initial_value: 89
        uint8                 :oplock_level,         label: 'Granted OpLock Level'
        uint8                 :flags,                label: 'Flags (Do Not Use)'
        uint32                :create_action,        label: 'Create Action'
        file_time             :create_time,          label: 'Create Time'
        file_time             :last_access,          label: 'Last Accessed Time'
        file_time             :last_write,           label: 'Last Write Time'
        file_time             :last_change,          label: 'Last Modified Time'
        uint64                :allocation_size,      label: 'Allocated Size'
        uint64                :end_of_file,          label: 'Size in Bytes'
        file_attributes       :file_attributes,      label: 'File Attributes'
        uint32                :reserved,             label: 'Reserved Space'
        smb2_fileid           :file_id,              label: 'File ID'
        uint32                :context_offset,       label: 'Create Context Offset',  initial_value: -> { context.abs_offset }
        uint32                :context_length,       label: 'Create Context Length',  initial_value: -> { context.do_num_bytes }

        array :context, label: 'Contexts', type: :create_context, read_until: :eof

        def initialize_instance
          super
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
