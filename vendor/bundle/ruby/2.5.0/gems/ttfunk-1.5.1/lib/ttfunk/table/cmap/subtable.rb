require_relative '../../reader'

module TTFunk
  class Table
    class Cmap
      class Subtable
        include Reader

        attr_reader :platform_id
        attr_reader :encoding_id
        attr_reader :format

        ENCODING_MAPPINGS = {
          mac_roman: { platform_id: 1, encoding_id: 0 }.freeze,
          # Use microsoft unicode, instead of generic unicode, for optimal
          # Windows support
          unicode: { platform_id: 3, encoding_id: 1 }.freeze,
          unicode_ucs4: { platform_id: 3, encoding_id: 10 }.freeze
        }.freeze

        def self.encode(charmap, encoding)
          case encoding
          when :mac_roman
            result = Format00.encode(charmap)
          when :unicode
            result = Format04.encode(charmap)
          when :unicode_ucs4
            result = Format12.encode(charmap)
          else
            raise NotImplementedError,
              "encoding #{encoding.inspect} is not supported"
          end

          mapping = ENCODING_MAPPINGS[encoding]

          # platform-id, encoding-id, offset
          result[:subtable] = [
            mapping[:platform_id],
            mapping[:encoding_id],
            12,
            result[:subtable]
          ].pack('nnNA*')

          result
        end

        def initialize(file, table_start)
          @file = file
          @platform_id, @encoding_id, @offset = read(8, 'nnN')
          @offset += table_start

          parse_from(@offset) do
            @format = read(2, 'n').first

            case @format
            when 0  then extend(TTFunk::Table::Cmap::Format00)
            when 4  then extend(TTFunk::Table::Cmap::Format04)
            when 6  then extend(TTFunk::Table::Cmap::Format06)
            when 10 then extend(TTFunk::Table::Cmap::Format10)
            when 12 then extend(TTFunk::Table::Cmap::Format12)
            end

            parse_cmap!
          end
        end

        def unicode?
          platform_id == 3 && (encoding_id == 1 || encoding_id == 10) &&
            format != 0 ||
            platform_id == 0 && format != 0
        end

        def supported?
          false
        end

        def [](_code)
          raise NotImplementedError, "cmap format #{@format} is not supported"
        end

        private

        def parse_cmap!
          # do nothing...
        end
      end
    end
  end
end

require_relative 'format00'
require_relative 'format04'
require_relative 'format06'
require_relative 'format10'
require_relative 'format12'
