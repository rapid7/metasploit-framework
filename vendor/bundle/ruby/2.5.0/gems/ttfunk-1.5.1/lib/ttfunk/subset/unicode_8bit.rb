require 'set'
require_relative 'base'

module TTFunk
  module Subset
    class Unicode8Bit < Base
      def initialize(original)
        super
        @subset = { 0x20 => 0x20 }
        @unicodes = { 0x20 => 0x20 }
        @next = 0x21 # apparently, PDF's don't like to use chars between 0-31
      end

      def unicode?
        true
      end

      def to_unicode_map
        @subset.dup
      end

      def use(character)
        unless @unicodes.key?(character)
          @subset[@next] = character
          @unicodes[character] = @next
          @next += 1
        end
      end

      def covers?(character)
        @unicodes.key?(character) || @next < 256
      end

      def includes?(character)
        @unicodes.key?(character)
      end

      def from_unicode(character)
        @unicodes[character]
      end

      protected

      def new_cmap_table(_options)
        mapping = @subset.each_with_object({}) do |(code, unicode), map|
          map[code] = unicode_cmap[unicode]
          map
        end

        # since we're mapping a subset of the unicode glyphs into an
        # arbitrary 256-character space, the actual encoding we're
        # using is irrelevant. We choose MacRoman because it's a 256-character
        # encoding that happens to be well-supported in both TTF and
        # PDF formats.
        TTFunk::Table::Cmap.encode(mapping, :mac_roman)
      end

      def original_glyph_ids
        ([0] + @unicodes.keys.map { |unicode| unicode_cmap[unicode] }).uniq.sort
      end
    end
  end
end
