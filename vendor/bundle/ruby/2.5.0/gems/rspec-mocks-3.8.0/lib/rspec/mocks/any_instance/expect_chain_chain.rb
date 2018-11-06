module RSpec
  module Mocks
    module AnyInstance
      # @private
      class ExpectChainChain < StubChain
        def initialize(*args)
          super
          @expectation_fulfilled = false
        end

        def expectation_fulfilled?
          @expectation_fulfilled
        end

        def playback!(instance)
          super.tap { @expectation_fulfilled = true }
        end

      private

        def create_message_expectation_on(instance)
          ::RSpec::Mocks::ExpectChain.expect_chain_on(instance, *@expectation_args, &@expectation_block)
        end

        def invocation_order
          EmptyInvocationOrder
        end
      end
    end
  end
end
