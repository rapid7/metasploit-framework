module RuboCop
  module Cop
    module Layout
      class ExtraSpacingWithBinDataIgnored < ExtraSpacing

        def_node_matcher :bindata?, <<~PATTERN
          (class _ (const (const _ :BinData) _) _)
        PATTERN

        # Returns an array of ranges that should not be reported.
        #
        # Note that BinData classes are skipped in their entirety, as
        # these frequently have custom whitespace alignment to improve
        # readability.
        def ignored_ranges(ast)
          return [] unless ast
          return @ignored_ranges if @ignored_ranges

          ignored_bindata_ranges = on_node(:class, ast).map do |clazz|
            next unless bindata?(clazz)

            clazz.source_range.begin_pos..clazz.source_range.end_pos
          end.compact

          @ignored_ranges = super + ignored_bindata_ranges
        end
      end
    end
  end
end
