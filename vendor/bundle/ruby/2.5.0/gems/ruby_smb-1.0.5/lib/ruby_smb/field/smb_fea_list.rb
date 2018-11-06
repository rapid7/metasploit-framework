module RubySMB
  module Field
    # Class representing an SMB File Extended Attribute List as defined in
    # [2.2.1.2.2.1 SMB_FEA_LIST](https://msdn.microsoft.com/en-us/library/ff359296.aspx)
    class SmbFeaList < BinData::Record
      endian :little
      uint32  :size_of_list, label: 'Size of List in Bytes', initial_value: -> { fea_list.do_num_bytes }
      array   :fea_list, initial_length: 0 do
        smb_fea
      end
    end
  end
end
