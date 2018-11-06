module TTFunk
  class Table
    class Post
      module Format40
        def glyph_for(code)
          @map[code] || 0xFFFF
        end

        private

        def parse_format!
          @map = read(file.maximum_profile.num_glyphs * 2, 'N*')
        end
      end
    end
  end
end
