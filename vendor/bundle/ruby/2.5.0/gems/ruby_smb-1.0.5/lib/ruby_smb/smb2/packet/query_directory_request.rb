module RubySMB
  module SMB2
    module Packet
      # An SMB2 Query Directory Request Packet as defined in
      # [2.2.33 SMB2 QUERY_DIRECTORY Request](https://msdn.microsoft.com/en-us/library/cc246551.aspx)
      class QueryDirectoryRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::QUERY_DIRECTORY

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size,          label: 'Structure Size', initial_value: 33
        uint8        :file_information_class,  label: 'File Information Class'

        struct :flags do
          bit3  :reserved2,       label: 'Reserved Space'
          bit1  :reopen,          label: 'Reopen Search'
          bit1  :reserved,        label: 'Reserved Space'
          bit1  :index_specified, label: 'Start at Specified Index'
          bit1  :return_single,   label: 'Return Single Entry'
          bit1  :restart_scans,   label: 'Restart Enumeration from Start'
        end

        uint32        :file_index,    label: 'File Index'
        smb2_fileid   :file_id,       label: 'File ID'
        uint16        :name_offset,   label: 'File Name Offset',      initial_value: -> { name.abs_offset }
        uint16        :name_length,   label: 'File Name Length',      initial_value: -> { name.do_num_bytes }
        uint32        :output_length, label: 'Output Buffer Length'
        string16      :name,          label: 'Name/Search Pattern'

      end
    end
  end
end
