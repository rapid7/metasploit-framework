require_relative '../table'

module TTFunk
  class Table
    class Hmtx < Table
      attr_reader :metrics
      attr_reader :left_side_bearings
      attr_reader :widths

      def self.encode(hmtx, mapping)
        metrics = mapping.keys.sort.map do |new_id|
          metric = hmtx.for(mapping[new_id])
          [metric.advance_width, metric.left_side_bearing]
        end

        {
          number_of_metrics: metrics.length,
          table: metrics.flatten.pack('n*')
        }
      end

      HorizontalMetric = Struct.new(:advance_width, :left_side_bearing)

      def for(glyph_id)
        @metrics[glyph_id] ||
          HorizontalMetric.new(
            @metrics.last.advance_width,
            @left_side_bearings[glyph_id - @metrics.length]
          )
      end

      private

      def parse!
        @metrics = []

        file.horizontal_header.number_of_metrics.times do
          advance = read(2, 'n').first
          lsb     = read_signed(1).first
          @metrics.push HorizontalMetric.new(advance, lsb)
        end

        lsb_count = file.maximum_profile.num_glyphs -
          file.horizontal_header.number_of_metrics
        @left_side_bearings = read_signed(lsb_count)

        @widths = @metrics.map(&:advance_width)
        @widths += [@widths.last] * @left_side_bearings.length
      end
    end
  end
end
