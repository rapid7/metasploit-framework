module Net
  module NTLM

    class Int16LE < Field

      def initialize(opt)
        super(opt)
        @size = 2
      end

      def parse(str, offset=0)
        if @active and str.size >= offset + @size
          @value = str[offset, @size].unpack("v")[0]
          @size
        else
          0
        end
      end

      def serialize
        [@value].pack("v")
      end
    end

  end
end