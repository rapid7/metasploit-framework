module RSpec
  module Mocks
    # @private
    module AnyInstance
      # @private
      class Chain
        def initialize(recorder, *args, &block)
          @recorder          = recorder
          @expectation_args  = args
          @expectation_block = block
          @argument_list_matcher = ArgumentListMatcher::MATCH_ALL
        end

        # @private
        #
        # Provides convenience methods for recording customizations on message
        # expectations.
        module Customizations
          # @macro [attach] record
          #   @method $1(*args, &block)
          #   Records the `$1` message for playback against an instance that
          #   invokes a method stubbed or mocked using `any_instance`.
          #
          #   @see RSpec::Mocks::MessageExpectation#$1
          #
          def self.record(method_name)
            define_method(method_name) do |*args, &block|
              record(method_name, *args, &block)
            end
          end

          record :and_return
          record :and_raise
          record :and_throw
          record :and_yield
          record :and_call_original
          record :and_wrap_original
          record :with
          record :once
          record :twice
          record :thrice
          record :exactly
          record :times
          record :never
          record :at_least
          record :at_most
        end

        include Customizations

        # @private
        def playback!(instance)
          message_expectation = create_message_expectation_on(instance)
          messages.inject(message_expectation) do |object, message|
            object.__send__(*message.first, &message.last)
          end
        end

        # @private
        def constrained_to_any_of?(*constraints)
          constraints.any? do |constraint|
            messages.any? do |message|
              message.first.first == constraint
            end
          end
        end

        # @private
        def matches_args?(*args)
          @argument_list_matcher.args_match?(*args)
        end

        # @private
        def expectation_fulfilled!
          @expectation_fulfilled = true
        end

        def never
          AnyInstance.error_generator.raise_double_negation_error("expect_any_instance_of(MyClass)") if negated?
          super
        end

        def with(*args, &block)
          @argument_list_matcher = ArgumentListMatcher.new(*args)
          super
        end

      private

        def negated?
          messages.any? { |(message, *_), _| message == :never }
        end

        def messages
          @messages ||= []
        end

        def last_message
          messages.last.first.first unless messages.empty?
        end

        def record(rspec_method_name, *args, &block)
          verify_invocation_order(rspec_method_name, *args, &block)
          messages << [args.unshift(rspec_method_name), block]
          self
        end
      end
    end
  end
end
