module RSpec
  module Mocks
    # @private
    class OrderGroup
      def initialize
        @expectations = []
        @invocation_order = []
        @index = 0
      end

      # @private
      def register(expectation)
        @expectations << expectation
      end

      def invoked(message)
        @invocation_order << message
      end

      # @private
      def ready_for?(expectation)
        remaining_expectations.find(&:ordered?) == expectation
      end

      # @private
      def consume
        remaining_expectations.each_with_index do |expectation, index|
          next unless expectation.ordered?

          @index += index + 1
          return expectation
        end
        nil
      end

      # @private
      def handle_order_constraint(expectation)
        return unless expectation.ordered? && remaining_expectations.include?(expectation)
        return consume if ready_for?(expectation)
        expectation.raise_out_of_order_error
      end

      def verify_invocation_order(expectation)
        expectation.raise_out_of_order_error unless expectations_invoked_in_order?
        true
      end

      def clear
        @index = 0
        @invocation_order.clear
        @expectations.clear
      end

      def empty?
        @expectations.empty?
      end

    private

      def remaining_expectations
        @expectations[@index..-1] || []
      end

      def expectations_invoked_in_order?
        invoked_expectations == expected_invocations
      end

      def invoked_expectations
        @expectations.select { |e| e.ordered? && @invocation_order.include?(e) }
      end

      def expected_invocations
        @invocation_order.map { |invocation| expectation_for(invocation) }.compact
      end

      def expectation_for(message)
        @expectations.find { |e| message == e }
      end
    end
  end
end
