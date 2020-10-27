# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class HighlightSubstringStyler
          COLOR = '%bgmag'

          def initialize(substrings)
            @substrings = substrings
          end

          def style(value)
            value_cp = value.clone

            @substrings.each do |s|
              # Regex used to pull out matches and preserve case sensitivity
              matches = value_cp.scan(%r{#{Regexp.escape(s)}}i)

              matches.each do |m|
                value_cp.gsub!(m, COLOR + m + '%clr')
              end
            end

            value_cp
          end
        end
      end
    end
  end
end
