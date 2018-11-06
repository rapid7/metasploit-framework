module TTFunk
  module Reader
    private

      def io
        @file.contents
      end

      def read(bytes, format)
        io.read(bytes).unpack(format)
      end

      def read_signed(count)
        read(count * 2, 'n*').map { |i| to_signed(i) }
      end

      def to_signed(n)
        n >= 0x8000 ? -((n ^ 0xFFFF) + 1) : n
      end

      def parse_from(position)
        saved = io.pos
        io.pos = position
        result = yield position
        io.pos = saved
        result
      end

      # For debugging purposes
      def hexdump(string)
        bytes = string.unpack('C*')
        bytes.each_with_index do |c, i|
          printf('%02X', c)
          if (i + 1) % 16 == 0
            puts
          elsif (i + 1) % 8 == 0
            print '  '
          else
            print ' '
          end
        end
        puts unless bytes.length % 16 == 0
      end
  end
end
