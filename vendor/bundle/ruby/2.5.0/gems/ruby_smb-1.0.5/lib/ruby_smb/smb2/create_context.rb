module RubySMB
  module SMB2
    # An SMB2_CREATE_CONTEXT struct as defined in
    # [2.2.13.2 SMB2_CREATE_CONTEXT Request Values](https://msdn.microsoft.com/en-us/library/cc246504.aspx)
    class CreateContext < BinData::Record
      endian  :little

      uint32  :next_offset, label: 'Offset to next Context'
      uint16  :name_offset, label: 'Offset to Name/Tag',      initial_value:  -> { name.rel_offset }
      uint16  :name_length, label: 'Length of Name/Tag',      initial_value:  -> { name.length }
      uint16  :reserved,    label: 'Reserved Space'
      uint16  :data_offset, label: 'Offset to data',          initial_value:  -> { calc_data_offset }
      uint32  :data_length, label: 'Length of data',          initial_value:  -> { data.length }
      string  :name,        label: 'Name'
      uint32  :reserved2,   label: 'Reserved Space'
      string  :data,        label: 'Data'

      private

      def calc_data_offset
        if data.empty?
          0
        else
          data.rel_offset
        end
      end
    end
  end
end
