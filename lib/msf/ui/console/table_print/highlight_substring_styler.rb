# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class HighlightSubstringStyler
          HIGHLIGHT_COLOR = '%bgmag'
          RESET_COLOR = '%clr'

          def initialize(substrings)
            @substrings = substrings
          end

          def style(value)
            search_terms = @substrings.map { |substring| Regexp.escape(substring) }
            search_pattern = /#{search_terms.join('|')}/i

            value.gsub(search_pattern) { |match| "#{HIGHLIGHT_COLOR}#{match}#{RESET_COLOR}" }
          end
        end
      end
    end
  end
end
