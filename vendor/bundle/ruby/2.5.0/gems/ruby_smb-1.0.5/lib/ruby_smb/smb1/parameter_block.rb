module RubySMB
  module SMB1
    # Represents the ParameterBlock portion of an SMB1 Packet. The ParameterBlock will
    # always contain a word_count field that gives the size of the rest of
    # the data block in words.
    class ParameterBlock < BinData::Record
      endian  :little

      uint8   :word_count, label: 'Word Count', initial_value: -> { calculate_word_count }

      # Class method to stub word count calculation during
      # lazy evaluation.
      #
      # @param [Fixnum] will always return 0
      def self.calculate_word_count
        0
      end

      # Returns the name of all fields, other than word_count, in
      # the ParameterBlock as symbols.
      #
      # @return [Array<Symbol>] the names of all other ParameterBlock fields
      def self.parameter_fields
        fields = self.fields.collect(&:name)
        fields.reject { |field| field == :word_count }
      end

      # Calculates the size of the other fields in the ParameterBlock
      # in Words.
      #
      # @return [Fixnum] The size of the ParameterBlock in Words
      def calculate_word_count
        total_count = 0
        self.class.parameter_fields.each do |field_name|
          field_value = send(field_name)
          total_count += field_value.do_num_bytes
        end
        total_count.to_i / 2
      end
    end
  end
end
