# frozen_string_literal: true

#
# A ridiculously simple formatter for SimpleCov results.
#
module SimpleCov
  module Formatter
    class SimpleFormatter
      # Takes a SimpleCov::Result and generates a string out of it
      def format(result)
        output = "".dup
        result.groups.each do |name, files|
          output << "Group: #{name}\n"
          output << "=" * 40
          output << "\n"
          files.each do |file|
            output << "#{file.filename} (coverage: #{file.covered_percent.round(2)}%)\n"
          end
          output << "\n"
        end
        output
      end
    end
  end
end
