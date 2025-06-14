# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class CustomColorStyler
          RESET_COLOR = '%clr'.freeze
          # @param [Hash<String, String>] opts A hash of a String to find, and what color to use
          # For example: opts = { 'abc' => '%grn' }
          def initialize(opts = {})
            @highlight_terms = opts.clone
          end

          def style(value)
            if @highlight_terms.key?(value)
              return "#{@highlight_terms[value]}#{value}#{RESET_COLOR}"
            end

            colored_value = value

            # Maximal munch; consume the terms in order of length, from longest to shortest
            @highlight_terms.keys.sort_by { |key| -key.length }.each do |key|
              if value.include?(key)
                colored_value.gsub!(key, "#{@highlight_terms[key]}#{key}#{RESET_COLOR}")
              end
            end

            colored_value
          end

          # @param [Hash<String, String>] opts A hash of a String to find, and what color to use
          def merge!(opts)
            @highlight_terms.merge!(opts)
          end
        end
      end
    end
  end
end
