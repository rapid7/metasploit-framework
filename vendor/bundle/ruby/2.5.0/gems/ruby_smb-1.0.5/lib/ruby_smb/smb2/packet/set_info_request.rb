module RubySMB
  module SMB2
    module Packet
      # An SMB2 Set Info Request Packet as defined in
      # [2.2.39 SMB2 SET_INFO Request](https://msdn.microsoft.com/en-us/library/cc246560.aspx)
      class SetInfoRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::SET_INFO

        include RubySMB::Fscc::FileInformation

        endian :little

        smb2_header :smb2_header
        uint16      :structure_size,  label: 'Structure Size', initial_value: 33
        # Constants defined in RubySMB::SMB2::InfoType
        uint8       :info_type,       label: 'Info Type',      initial_value: RubySMB::SMB2::InfoType::SMB2_0_INFO_FILE
        uint8       :file_info_class, label: 'File Info Class'
        uint32      :buffer_length,   label: 'Buffer Length',  initial_value: -> { buffer.do_num_bytes }
        uint16      :buffer_offset,   label: 'Buffer Offset',  initial_value: -> { buffer.abs_offset }
        uint16      :reserved,        label: 'Reserved',       initial_value: 0

        struct :additional_information do
          bit1  :reserved,                       label: 'Reserved Space'
          bit1  :scope_security_information,     label: 'Scope Security Information'
          bit1  :attribute_security_information, label: 'Attribute Security Information'
          bit1  :label_security_information,     label: 'Label Security Information'
          bit1  :sacl_security_information,      label: 'SACL Security Information'
          bit1  :dacl_security_information,      label: 'DACL Security Information'
          bit1  :group_security_information,     label: 'Group Security Information'
          bit1  :owner_security_information,     label: 'Owner Security Information'
          # byte boundary
          bit8  :reserved2,                      label: 'Reserved Space'
          # byte boundary
          bit7  :reserved3,                      label: 'Reserved Space'
          bit1  :backup_security_information,    label: 'Backup Security Information'
          # byte boundary
          bit8  :reserved4,                      label: 'Reserved Space'
        end

        smb2_fileid :file_id, label: 'File ID'

        choice :buffer, label: 'Buffer', selection: -> { file_info_class } do
          file_directory_information         FILE_DIRECTORY_INFORMATION,         label: 'File Directory Information'
          file_full_directory_information    FILE_FULL_DIRECTORY_INFORMATION,    label: 'File Full Directory Information'
          file_both_directory_information    FILE_BOTH_DIRECTORY_INFORMATION,    label: 'File Both Directory Information'
          file_rename_information            FILE_RENAME_INFORMATION,            label: 'File Rename Information'
          file_names_information             FILE_NAMES_INFORMATION,             label: 'File Names Information'
          file_disposition_information       FILE_DISPOSITION_INFORMATION,       label: 'File Disposition Information'
          file_id_both_directory_information FILE_ID_BOTH_DIRECTORY_INFORMATION, label: 'File Id Both Directory Information'
          file_id_full_directory_information FILE_ID_FULL_DIRECTORY_INFORMATION, label: 'File Id Full Directory Information'
        end

      end
    end
  end
end
