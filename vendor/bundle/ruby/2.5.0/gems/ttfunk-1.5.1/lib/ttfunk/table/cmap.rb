module TTFunk
  class Table
    class Cmap < Table
      attr_reader :version
      attr_reader :tables

      def self.encode(charmap, encoding)
        result = Cmap::Subtable.encode(charmap, encoding)

        # pack 'version' and 'table-count'
        result[:table] = [0, 1, result.delete(:subtable)].pack('nnA*')
        result
      end

      def unicode
        # Because most callers just call .first on the result, put tables with
        # highest-number format first. Unsupported formats will be ignored.
        @unicode ||= @tables
                     .select { |table| table.unicode? && table.supported? }
                     .sort { |a, b| b.format <=> a.format }
      end

      private

      def parse!
        @version, table_count = read(4, 'nn')
        @tables = []

        table_count.times do
          @tables << Cmap::Subtable.new(file, offset)
        end
      end
    end
  end
end

require_relative 'cmap/subtable'
