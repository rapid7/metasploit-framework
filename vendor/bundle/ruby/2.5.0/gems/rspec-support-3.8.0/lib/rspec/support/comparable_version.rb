module RSpec
  module Support
    # @private
    class ComparableVersion
      include Comparable

      attr_reader :string

      def initialize(string)
        @string = string
      end

      def <=>(other)
        other = self.class.new(other) unless other.is_a?(self.class)

        return 0 if string == other.string

        longer_segment_count = [self, other].map { |version| version.segments.count }.max

        longer_segment_count.times do |index|
          self_segment = segments[index] || 0
          other_segment = other.segments[index] || 0

          if self_segment.class == other_segment.class
            result = self_segment <=> other_segment
            return result unless result == 0
          else
            return self_segment.is_a?(String) ? -1 : 1
          end
        end

        0
      end

      def segments
        @segments ||= string.scan(/[a-z]+|\d+/i).map do |segment|
          if segment =~ /\A\d+\z/
            segment.to_i
          else
            segment
          end
        end
      end
    end
  end
end
