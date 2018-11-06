module RubySMB
  module SMB1
    module BitField
      # The Capabilities bit-field for a NegotiateResponse as defined in
      # [2.2.4.52.2 Response](https://msdn.microsoft.com/en-us/library/ee441946.aspx)
      class Capabilities < BinData::Record
        endian :little
        bit1    :level_2_oplocks,         label: 'Level II OpLocks', initial_value: 1
        bit1    :nt_status,               label: 'NTStatus Codes', initial_value: 1
        bit1    :rpc_remote_apis,         label: 'MS-RPC Supported'
        bit1    :nt_smbs,                 label: 'NT Lan Manager', initial_value: 1
        bit1    :large_files,             label: '64-bit File offsets'
        bit1    :unicode,                 label: 'Unicode Strings', initial_value: 1
        bit1    :mpx_mode,                label: 'Multiplex Mode'
        bit1    :raw_mode,                label: 'Raw Mode'
        # Byte Border
        bit1    :large_writex,            label: 'Large Write Andx'
        bit1    :large_readx,             label: 'Large Read Andx'
        bit1    :info_level_passthru,     label: 'Infolevel Passthrough'
        bit1    :dfs,                     label: 'DFS'
        bit1    :reserved1,               label: 'Reserved',             initial_value: 0
        bit1    :bulk_transfer,           label: 'Bulk Transfer',        initial_value: 0
        bit1    :nt_find,                 label: 'Trans2 Find'
        bit1    :lock_and_read,           label: 'Lock And Read'
        # Byte Border
        bit1    :unix,                    label: 'UNIX Extensions'
        bit6    :reserved2,               label: 'Reserved', initial_value: 0
        bit1    :lwio,                    label: 'LWIO IOCTL/FSCTL'
        # Byte Border
        bit1    :extended_security,       label: 'Extended Security', initial_value: 1
        bit1    :reserved3,               label: 'Reserved', initial_value: 0
        bit1    :dynamic_reauth,          label: 'Dynamic Reauth'
        bit3    :reserved4,               label: 'Reserved', initial_value: 0
        bit1    :compressed_data,         label: 'Compressed Data'
        bit1    :reserved5,               label: 'Reserved', initial_value: 0
      end
    end
  end
end
