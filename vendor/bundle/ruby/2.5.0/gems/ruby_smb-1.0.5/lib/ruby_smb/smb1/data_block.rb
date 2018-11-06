module RubySMB
  module SMB1
    # Represents the DataBlock portion of an SMB1 Packet. The DataBlock will
    # always contain a byte_count field that gives the size of the rest of
    # the data block in bytes.
    class DataBlock < BinData::Record
      endian :little

      uint16 :byte_count, label: 'Byte Count', initial_value: -> { calculate_byte_count }

      # Class method to stub byte count calculation during
      # lazy evaluation.
      #
      # @return [Fixnum] will always return 0
      def self.calculate_byte_count
        0
      end

      # Returns the name of all fields, other than byte_count, in
      # the DataBlock as symbols.
      #
      # @return [Array<Symbol>] the names of all other DataBlock fields
      def self.data_fields
        fields = self.fields.collect(&:name)
        fields.reject { |field| field == :byte_count }
      end

      # Calculates the size of the other fields in the DataBlock
      # in Bytes.
      #
      # @return [Fixnum] The size of the DataBlock in Words
      def calculate_byte_count
        total_count = 0
        self.class.data_fields.each do |field_name|
          next unless field_enabled?(field_name)
          field_value = send(field_name)
          total_count += field_value.do_num_bytes
        end
        total_count
      end

      def field_enabled?(field_name)
        send("#{field_name}?".to_sym)
      end
    end
  end
end
