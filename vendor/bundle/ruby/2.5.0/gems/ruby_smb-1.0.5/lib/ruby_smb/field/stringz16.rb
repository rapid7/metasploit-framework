module RubySMB
  module Field
    # Represents a NULL-Terminated String in UTF-16
    class Stringz16 < BinData::Stringz
      def assign(val)
        super(binary_string(val.encode('utf-16le')))
      end

      def snapshot
        # override to always remove trailing zero bytes
        result = _value
        result = trim_and_zero_terminate(result)
        result.chomp("\0\0").force_encoding('utf-16le')
      end

      private

      def append_zero_byte_if_needed!(str)
        str << "\0\0" if str.empty? || !str.end_with?("\0\0")
      end

      # Override parent on {BinData::Stringz} to use
      # a double NULL-byte instead of a single NULL-byte
      # as a terminator
      # @see BinData::Stringz
      def read_and_return_value(io)
        max_length = eval_parameter(:max_length)
        str = ''
        i = 0
        ch = nil

        # read until double NULL-byte or we have read in the max number of bytes
        while (ch != "\0\0") && (i != max_length)
          ch = io.readbytes(2)
          str << ch
          i += 2
        end

        trim_and_zero_terminate(str)
      end

      # Override parent method of #truncate_after_first_zero_byte! on
      # {BinData::Stringz} to use two consecutive NULL-bytes as the terimnator
      # instead of a single NULL-nyte.
      # @see BinData::Stringz
      def truncate_after_first_zero_byte!(str)
        str.sub!(/([^\0]*\0\0\0).*/, '\1')
      end
    end
  end
end
