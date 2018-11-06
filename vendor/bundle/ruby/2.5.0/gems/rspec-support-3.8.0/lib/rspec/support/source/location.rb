module RSpec
  module Support
    class Source
      # @private
      # Represents a source location of node or token.
      Location = Struct.new(:line, :column) do
        include Comparable

        def self.location?(array)
          array.is_a?(Array) && array.size == 2 && array.all? { |e| e.is_a?(Integer) }
        end

        def <=>(other)
          line_comparison = (line <=> other.line)
          return line_comparison unless line_comparison == 0
          column <=> other.column
        end
      end
    end
  end
end
