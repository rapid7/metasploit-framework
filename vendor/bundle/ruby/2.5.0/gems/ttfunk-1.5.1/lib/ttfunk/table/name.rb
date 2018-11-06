require_relative '../table'
require 'digest/sha1'

module TTFunk
  class Table
    class Name < Table
      class String < ::String
        attr_reader :platform_id
        attr_reader :encoding_id
        attr_reader :language_id

        def initialize(text, platform_id, encoding_id, language_id)
          super(text)
          @platform_id = platform_id
          @encoding_id = encoding_id
          @language_id = language_id
        end

        def strip_extended
          stripped = gsub(/[\x00-\x19\x80-\xff]/n, '')
          stripped = '[not-postscript]' if stripped.empty?
          stripped
        end
      end

      attr_reader :strings

      attr_reader :copyright
      attr_reader :font_family
      attr_reader :font_subfamily
      attr_reader :unique_subfamily
      attr_reader :font_name
      attr_reader :version
      attr_reader :trademark
      attr_reader :manufacturer
      attr_reader :designer
      attr_reader :description
      attr_reader :vendor_url
      attr_reader :designer_url
      attr_reader :license
      attr_reader :license_url
      attr_reader :preferred_family
      attr_reader :preferred_subfamily
      attr_reader :compatible_full
      attr_reader :sample_text

      def self.encode(names, key = '')
        tag = Digest::SHA1.hexdigest(key)[0, 6]

        postscript_name = Name::String.new(
          "#{tag}+#{names.postscript_name}", 1, 0, 0
        )

        strings = names.strings.dup
        strings[6] = [postscript_name]
        str_count = strings.inject(0) { |sum, (_, list)| sum + list.length }

        table = [0, str_count, 6 + 12 * str_count].pack('n*')
        strtable = ''

        strings.each do |id, list|
          list.each do |string|
            table << [
              string.platform_id, string.encoding_id, string.language_id, id,
              string.length, strtable.length
            ].pack('n*')
            strtable << string
          end
        end

        table << strtable
      end

      def postscript_name
        return @postscript_name if @postscript_name
        font_family.first || 'unnamed'
      end

      private

      def parse!
        count, string_offset = read(6, 'x2n*')

        entries = []
        count.times do
          platform, encoding, language, id, length, start_offset =
            read(12, 'n*')
          entries << {
            platform_id: platform,
            encoding_id: encoding,
            language_id: language,
            name_id: id,
            length: length,
            offset: offset + string_offset + start_offset
          }
        end

        @strings = Hash.new { |h, k| h[k] = [] }

        count.times do |i|
          io.pos = entries[i][:offset]
          text = io.read(entries[i][:length])
          @strings[entries[i][:name_id]] << Name::String.new(
            text,
            entries[i][:platform_id],
            entries[i][:encoding_id],
            entries[i][:language_id]
          )
        end

        @copyright = @strings[0]
        @font_family = @strings[1]
        @font_subfamily = @strings[2]
        @unique_subfamily = @strings[3]
        @font_name = @strings[4]
        @version = @strings[5]
        # should only be ONE postscript name
        @postscript_name = @strings[6].first.strip_extended
        @trademark = @strings[7]
        @manufacturer = @strings[8]
        @designer = @strings[9]
        @description = @strings[10]
        @vendor_url = @strings[11]
        @designer_url = @strings[12]
        @license = @strings[13]
        @license_url = @strings[14]
        @preferred_family = @strings[16]
        @preferred_subfamily = @strings[17]
        @compatible_full = @strings[18]
        @sample_text = @strings[19]
      end
    end
  end
end
