require 'set'
require_relative 'base'

module TTFunk
  module Subset
    class Unicode < Base
      def initialize(original)
        super
        @subset = Set.new
      end

      def unicode?
        true
      end

      def to_unicode_map
        @subset.each_with_object({}) { |code, map| map[code] = code }
      end

      def use(character)
        @subset << character
      end

      def covers?(_character)
        true
      end

      def includes?(character)
        @subset.includes(character)
      end

      def from_unicode(character)
        character
      end

      protected

      def new_cmap_table(_options)
        mapping = @subset.each_with_object({}) do |code, map|
          map[code] = unicode_cmap[code]
        end
        TTFunk::Table::Cmap.encode(mapping, :unicode)
      end

      def original_glyph_ids
        ([0] + @subset.map { |code| unicode_cmap[code] }).uniq.sort
      end
    end
  end
end
