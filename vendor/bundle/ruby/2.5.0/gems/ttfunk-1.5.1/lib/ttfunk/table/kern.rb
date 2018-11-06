require_relative '../table'

module TTFunk
  class Table
    class Kern < Table
      attr_reader :version
      attr_reader :tables

      def self.encode(kerning, mapping)
        return nil unless kerning.exists? && kerning.tables.any?
        tables = kerning.tables.map { |table| table.recode(mapping) }.compact
        return nil if tables.empty?

        [0, tables.length, tables.join].pack('nnA*')
      end

      private

      def parse!
        @version, num_tables = read(4, 'n*')
        @tables = []

        if @version == 1 # Mac OS X fonts
          @version = (@version << 16) + num_tables
          num_tables = read(4, 'N').first
          parse_version_1_tables(num_tables)
        else
          parse_version_0_tables(num_tables)
        end
      end

      def parse_version_0_tables(_num_tables)
        # It looks like some MS fonts report their kerning subtable lengths
        # wrong. In one case, the length was reported to be some 19366, and yet
        # the table also claimed to hold 14148 pairs (each pair consisting of
        # 6 bytes).  You do the math!
        #
        # We're going to assume that the microsoft fonts hold only a single
        # kerning subtable, which occupies the entire length of the kerning
        # table. Worst case, we lose any other subtables that the font contains,
        # but it's better than reading a truncated kerning table.
        #
        # And what's more, it appears to work. So.
        version, length, coverage = read(6, 'n*')
        format = coverage >> 8

        add_table(
          format,
          version: version,
          length: length,
          coverage: coverage,
          data: raw[10..-1],
          vertical: (coverage & 0x1 == 0),
          minimum: (coverage & 0x2 != 0),
          cross: (coverage & 0x4 != 0),
          override: (coverage & 0x8 != 0)
        )
      end

      def parse_version_1_tables(num_tables)
        num_tables.times do
          length, coverage, tuple_index = read(8, 'Nnn')
          format = coverage & 0x0FF

          add_table(
            format,
            length: length,
            coverage: coverage,
            tuple_index: tuple_index,
            data: io.read(length - 8),
            vertical: (coverage & 0x8000 != 0),
            cross: (coverage & 0x4000 != 0),
            variation: (coverage & 0x2000 != 0)
          )
        end
      end

      def add_table(format, attributes = {})
        if format == 0
          @tables << Kern::Format0.new(attributes)
        end
        # Unsupported kerning tables are silently ignored
      end
    end
  end
end

require_relative 'kern/format0'
