require_relative '../../encoding/mac_roman'
require_relative '../../encoding/windows_1252'

module TTFunk
  class Table
    class Cmap
      module Format00
        attr_reader :language
        attr_reader :code_map

        # Expects a hash mapping character codes to glyph ids (where the
        # glyph ids are from the original font). Returns a hash including
        # a new map (:charmap) that maps the characters in charmap to a
        # another hash containing both the old (:old) and new (:new) glyph
        # ids. The returned hash also includes a :subtable key, which contains
        # the encoded subtable for the given charmap.
        def self.encode(charmap)
          next_id = 0
          glyph_indexes = Array.new(256, 0)
          glyph_map = { 0 => 0 }

          new_map = charmap.keys.sort.each_with_object({}) do |code, map|
            glyph_map[charmap[code]] ||= next_id += 1
            map[code] = { old: charmap[code], new: glyph_map[charmap[code]] }
            glyph_indexes[code] = glyph_map[charmap[code]]
            map
          end

          # format, length, language, indices
          subtable = [0, 262, 0, *glyph_indexes].pack('nnnC*')

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
          @language = read(4, 'x2n')
          @code_map = read(256, 'C*')
        end
      end
    end
  end
end
