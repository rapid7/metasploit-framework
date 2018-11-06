module RSpec
  module Core
    # @private
    class Profiler
      NOTIFICATIONS = [:example_group_started, :example_group_finished, :example_started]

      def initialize
        @example_groups = Hash.new { |h, k| h[k] = { :count => 0 } }
      end

      attr_reader :example_groups

      def example_group_started(notification)
        return unless notification.group.top_level?

        @example_groups[notification.group][:start] = Time.now
        @example_groups[notification.group][:description] = notification.group.top_level_description
      end

      def example_group_finished(notification)
        return unless notification.group.top_level?

        group = @example_groups[notification.group]
        return unless group.key?(:start)
        group[:total_time] = Time.now - group[:start]
      end

      def example_started(notification)
        group = notification.example.example_group.parent_groups.last
        @example_groups[group][:count] += 1
      end
    end
  end
end
