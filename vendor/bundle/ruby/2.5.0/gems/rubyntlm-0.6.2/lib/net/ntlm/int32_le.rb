module Net
  module NTLM

    class Int32LE < Field
      def initialize(opt)
        super(opt)
        @size = 4
      end

      def parse(str, offset=0)
        if @active and str.size >= offset + @size
          @value = str.slice(offset, @size).unpack("V")[0]
          @size
        else
          0
        end
      end

      def serialize
        [@value].pack("V") if @active
      end
    end

  end
end