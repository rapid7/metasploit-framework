module Net
  module NTLM

    class Int64LE < Field
      def initialize(opt)
        super(opt)
        @size = 8
      end

      def parse(str, offset=0)
        if @active and str.size >= offset + @size
          d, u = str.slice(offset, @size).unpack("V2")
          @value = (u * 0x100000000 + d)
          @size
        else
          0
        end
      end

      def serialize
        [@value & 0x00000000ffffffff, @value >> 32].pack("V2") if @active
      end
    end

  end
end