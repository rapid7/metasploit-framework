require 'set'

require_relative 'base'
require_relative '../encoding/windows_1252'

module TTFunk
  module Subset
    class Windows1252 < Base
      def initialize(original)
        super
        @subset = Array.new(256)
      end

      def to_unicode_map
        Encoding::Windows1252::TO_UNICODE
      end

      def use(character)
        @subset[Encoding::Windows1252::FROM_UNICODE[character]] = character
      end

      def covers?(character)
        Encoding::Windows1252.covers?(character)
      end

      def includes?(character)
        code = Encoding::Windows1252::FROM_UNICODE[character]
        code && @subset[code]
      end

      def from_unicode(character)
        Encoding::Windows1252::FROM_UNICODE[character]
      end

      protected

      def new_cmap_table(_options)
        mapping = {}
        @subset.each_with_index do |unicode, cp1252|
          mapping[cp1252] = unicode_cmap[unicode] if cp1252
        end

        # yes, I really mean "mac roman". TTF has no cp1252 encoding, and the
        # alternative would be to encode it using a format 4 unicode table,
        # which is overkill. for our purposes, mac-roman suffices. (If we were
        # building a _real_ font, instead of a PDF-embeddable subset, things
        # would probably be different.)
        TTFunk::Table::Cmap.encode(mapping, :mac_roman)
      end

      def original_glyph_ids
        ([0] + @subset.map { |unicode| unicode && unicode_cmap[unicode] })
          .compact.uniq.sort
      end
    end
  end
end
