module RubySMB
  module SMB1
    module BitField
      # Represents a CreateOptions BitField as used by both the NT_CREATE_ANDX
      # and the NT_TRANSACT_CREATE Requests. The definition for this field can be found at
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx) and
      # [2.2.4.9.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246332.aspx)
      class CreateOptions < BinData::Record
        endian  :little
        bit1    :create_tree_connection,      label: 'Create Tree Connection'
        bit1    :non_directory_file,          label: 'Non-Directory File'
        bit1    :synchronous_io_nonalert,     label: 'Synchronous IO Nonalert'
        bit1    :synchronous_io_alert,        label: 'Synchronous IO Alert'
        bit1    :no_intermediate_buffer,      label: 'No Intermediate Buffering'
        bit1    :sequential_only,             label: 'Sequential Only'
        bit1    :write_through,               label: 'Write Through'
        bit1    :directory_file,              label: 'Directory File'
        # Byte Boundary
        bit1    :no_compression,              label: 'No Compression'
        bit1    :open_for_backup_intent,      label: 'Open For Backup Intent'
        bit1    :open_by_file_id,             label: 'Open by File ID'
        bit1    :delete_on_close,             label: 'Delete on Close'
        bit1    :random_access,               label: 'Random Access'
        bit1    :open_for_recovery,           label: 'Open for Recovery'
        bit1    :no_ea_knowledge,             label: 'No EA Knowledge'
        bit1    :complete_if_oplocked,        label: 'Complete if OPLocked'
        # Byte Boundary
        bit1    :open_for_free_space_query,   label: 'Open for Free Space Query'
        bit1    :open_no_recall,              label: 'Open No Recall'
        bit1    :open_reparse_point,          label: 'Open Reparse Point'
        bit1    :reserve_opfilter,            label: 'Reserve OPFilter'
        bit4    :reserved,                    label: 'Reserved Space'
        # Byte Boundary
        bit8    :reserved2,                   label: 'Reserved Space'
      end
    end
  end
end
