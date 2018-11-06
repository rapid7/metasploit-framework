module RSpec
  module Mocks
    module AnyInstance
      # @private
      class StubChain < Chain
        # @private
        def expectation_fulfilled?
          true
        end

      private

        def create_message_expectation_on(instance)
          proxy = ::RSpec::Mocks.space.proxy_for(instance)
          method_name, opts = @expectation_args
          opts = (opts || {}).merge(:expected_form => IGNORED_BACKTRACE_LINE)

          stub = proxy.add_stub(method_name, opts, &@expectation_block)
          @recorder.stubs[stub.message] << stub

          if RSpec::Mocks.configuration.yield_receiver_to_any_instance_implementation_blocks?
            stub.and_yield_receiver_to_implementation
          end

          stub
        end

        InvocationOrder =
          {
            :and_return => [:with, nil],
            :and_raise => [:with, nil],
            :and_yield => [:with, :and_yield, nil],
            :and_throw => [:with, nil],
            :and_call_original => [:with, nil],
            :and_wrap_original => [:with, nil]
          }.freeze

        EmptyInvocationOrder = {}.freeze

        def invocation_order
          InvocationOrder
        end

        def verify_invocation_order(rspec_method_name, *_args, &_block)
          return if invocation_order.fetch(rspec_method_name, [nil]).include?(last_message)
          raise NoMethodError, "Undefined method #{rspec_method_name}"
        end
      end
    end
  end
end
