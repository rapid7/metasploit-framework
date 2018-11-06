module TTFunk
  class Table
    class Post
      module Format30
        def glyph_for(_code)
          '.notdef'
        end

        private

        def parse_format!
          # do nothing. Format 3 is easy-sauce.
        end
      end
    end
  end
end
