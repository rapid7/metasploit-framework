module TTFunk
  class Table
    class Cmap
      module Format10
        attr_reader :language
        attr_reader :code_map

        def self.encode(charmap)
          next_id = 0
          glyph_map = { 0 => 0 }

          sorted_chars = charmap.keys.sort
          low_char = sorted_chars.first
          high_char = sorted_chars.last
          entry_count = 1 + high_char - low_char
          glyph_indexes = Array.new(entry_count, 0)

          new_map = charmap.keys.sort.each_with_object({}) do |code, map|
            glyph_map[charmap[code]] ||= next_id += 1
            map[code] = { old: charmap[code], new: glyph_map[charmap[code]] }
            glyph_indexes[code - low_char] = glyph_map[charmap[code]]
          end

          subtable = [
            10, 0, 20 + entry_count * 4, 0, low_char, entry_count,
            *glyph_indexes
          ].pack('nnN*')

          { charmap: new_map, subtable: subtable, max_glyph_id: next_id + 1 }
        end

        def [](code)
          @code_map[code] || 0
        end

        def supported?
          true
        end

        private

        def parse_cmap!
          fractional_version, @language, firstcode, entrycount =
            read(18, 'nx4NNN')
          if fractional_version != 0
            raise NotImplementedError,
              "cmap version 10.#{fractional_version} is not supported"
          end
          @code_map = {}
          (firstcode...(firstcode + entrycount)).each do |code|
            @code_map[code] = read(2, 'n').first & 0xFFFF
          end
        end
      end
    end
  end
end
