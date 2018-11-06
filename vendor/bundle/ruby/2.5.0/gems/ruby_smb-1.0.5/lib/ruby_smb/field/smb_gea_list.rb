module RubySMB
  module Field
    # Class representing an SMB Get Extended Attribute List as defined in
    # [2.2.1.2.1.1 SMB_GEA_LIST](https://msdn.microsoft.com/en-us/library/ff359447.aspx)
    class SmbGeaList < BinData::Record
      endian :little
      uint32  :size_of_list, label: 'Size of List in Bytes', initial_value: -> { self.do_num_bytes }
      array   :gea_list, initial_length: 0 do
        smb_gea
      end
    end
  end
end
