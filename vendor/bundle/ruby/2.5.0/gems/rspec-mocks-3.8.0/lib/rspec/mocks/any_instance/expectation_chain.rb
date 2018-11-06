module RSpec
  module Mocks
    module AnyInstance
      # @private
      class ExpectationChain < Chain
        def expectation_fulfilled?
          @expectation_fulfilled || constrained_to_any_of?(:never)
        end

        def initialize(*args, &block)
          @expectation_fulfilled = false
          super
        end

      private

        def verify_invocation_order(_rspec_method_name, *_args, &_block)
        end
      end

      # @private
      class PositiveExpectationChain < ExpectationChain
      private

        def create_message_expectation_on(instance)
          proxy = ::RSpec::Mocks.space.proxy_for(instance)
          method_name, opts = @expectation_args
          opts = (opts || {}).merge(:expected_form => IGNORED_BACKTRACE_LINE)

          me = proxy.add_message_expectation(method_name, opts, &@expectation_block)
          if RSpec::Mocks.configuration.yield_receiver_to_any_instance_implementation_blocks?
            me.and_yield_receiver_to_implementation
          end

          me
        end

        ExpectationInvocationOrder =
          {
            :and_return => [:with, nil],
            :and_raise => [:with, nil],
          }.freeze

        def invocation_order
          ExpectationInvocationOrder
        end
      end
    end
  end
end
