# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class HighlightSubstringStyler
          HIGHLIGHT_COLOR = '%bgmag'
          RESET_COLOR = '%clr'

          # @param [Array<Regex|String>] terms An array of either strings or regular expressions to highlight
          def initialize(terms)
            @highlight_terms = /#{Regexp.union(terms.compact).source}/i
          end

          def style(value)
            value.gsub(@highlight_terms) { |match| "#{HIGHLIGHT_COLOR}#{match}#{RESET_COLOR}" }
          end
        end
      end
    end
  end
end
