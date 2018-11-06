module RubySMB
  module Field
    # Represents a String in UTF-16LE
    class String16 < BinData::String
      def assign(val)
        super(val.encode('utf-16le'))
      end

      def snapshot
        super.force_encoding('utf-16le')
      end
    end
  end
end
