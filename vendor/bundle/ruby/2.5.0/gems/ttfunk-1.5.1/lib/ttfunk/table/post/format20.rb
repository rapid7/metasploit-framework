require_relative 'format10'
require 'stringio'

module TTFunk
  class Table
    class Post
      module Format20
        include Format10

        def glyph_for(code)
          index = @glyph_name_index[code]
          if index <= 257
            POSTSCRIPT_GLYPHS[index]
          else
            @names[index - 258] || '.notdef'
          end
        end

        private

        def parse_format!
          number_of_glyphs = read(2, 'n').first
          @glyph_name_index = read(number_of_glyphs * 2, 'n*')
          @names = []

          strings = StringIO.new(io.read(offset + length - io.pos))
          until strings.eof?
            length = strings.read(1).unpack('C').first
            @names << strings.read(length)
          end
        end
      end
    end
  end
end
