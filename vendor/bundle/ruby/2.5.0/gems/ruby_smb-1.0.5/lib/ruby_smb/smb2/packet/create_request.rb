module RubySMB
  module SMB2
    module Packet
      # An SMB2 Create Request Packet as defined in
      # [2.2.13 SMB2 CREATE Request](https://msdn.microsoft.com/en-us/library/cc246502.aspx)
      class CreateRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::CREATE

        require 'ruby_smb/smb1/bit_field/create_options'

        endian :little
        smb2_header           :smb2_header
        uint16                :structure_size,       label: 'Structure Size',              initial_value: 57
        uint8                 :security_flag,        label: 'Security Flags(Do not Use)',  initial_value: 0
        uint8                 :requested_oplock,     label: 'Requested OpLock Level',      initial_value: 0
        uint32                :impersonation_level,  label: 'Impersonation Level'
        uint64                :create_flags,         label: 'Create Flags(Do not use)',    initial_value: 0
        uint64                :reserved,             label: 'Reserved',                    initial_value: 0

        choice :desired_access, selection: -> { file_attributes.directory } do
          file_access_mask      0, label: 'Desired Access'
          directory_access_mask 1, label: 'Desired Access'
        end

        file_attributes :file_attributes, label: 'File Attributes'

        struct :share_access do
          bit5  :reserved,          label: 'Reserved Space'
          bit1  :delete_access,     label: 'Share Delete Access'
          bit1  :write_access,      label: 'Share Write Access'
          bit1  :read_access,       label: 'Share Read Access'
          # byte boundary
          bit8  :reserved2, label: 'Reserved Space'
          bit8  :reserved3, label: 'Reserved Space'
          bit8  :reserved4, label: 'Reserved Space'
        end

        uint32          :create_disposition, label: 'Create Disposition'
        create_options  :create_options
        uint16          :name_offset,         label: 'Name Offset',            initial_value: -> { name.abs_offset }
        uint16          :name_length,         label: 'Name Length',            initial_value: -> { name.do_num_bytes }
        uint32          :context_offset,      label: 'Create Context Offset',  initial_value: -> { context.abs_offset }
        uint32          :context_length,      label: 'Create Context Length',  initial_value: -> { context.do_num_bytes }
        string16        :name,                label: 'File Name'
        uint32          :reserved5,           label: 'Reserved Space'

        array :context, label: 'Contexts', type: :create_context, read_until: :eof

      end
    end
  end
end
