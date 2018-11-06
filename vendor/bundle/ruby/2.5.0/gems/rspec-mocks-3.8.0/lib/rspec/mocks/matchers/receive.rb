RSpec::Support.require_rspec_mocks 'matchers/expectation_customization'

module RSpec
  module Mocks
    module Matchers
      # @private
      class Receive
        include Matcher

        def initialize(message, block)
          @message                 = message
          @block                   = block
          @recorded_customizations = []
        end

        def name
          "receive"
        end

        def description
          describable.description_for("receive")
        end

        def setup_expectation(subject, &block)
          warn_if_any_instance("expect", subject)
          @describable = setup_mock_proxy_method_substitute(subject, :add_message_expectation, block)
        end
        alias matches? setup_expectation

        def setup_negative_expectation(subject, &block)
          # ensure `never` goes first for cases like `never.and_return(5)`,
          # where `and_return` is meant to raise an error
          @recorded_customizations.unshift ExpectationCustomization.new(:never, [], nil)

          warn_if_any_instance("expect", subject)

          setup_expectation(subject, &block)
        end
        alias does_not_match? setup_negative_expectation

        def setup_allowance(subject, &block)
          warn_if_any_instance("allow", subject)
          setup_mock_proxy_method_substitute(subject, :add_stub, block)
        end

        def setup_any_instance_expectation(subject, &block)
          setup_any_instance_method_substitute(subject, :should_receive, block)
        end

        def setup_any_instance_negative_expectation(subject, &block)
          setup_any_instance_method_substitute(subject, :should_not_receive, block)
        end

        def setup_any_instance_allowance(subject, &block)
          setup_any_instance_method_substitute(subject, :stub, block)
        end

        MessageExpectation.public_instance_methods(false).each do |method|
          next if method_defined?(method)

          define_method(method) do |*args, &block|
            @recorded_customizations << ExpectationCustomization.new(method, args, block)
            self
          end
        end

      private

        def describable
          @describable ||= DefaultDescribable.new(@message)
        end

        def warn_if_any_instance(expression, subject)
          return unless AnyInstance::Proxy === subject

          RSpec.warning(
            "`#{expression}(#{subject.klass}.any_instance).to` " \
            "is probably not what you meant, it does not operate on " \
            "any instance of `#{subject.klass}`. " \
            "Use `#{expression}_any_instance_of(#{subject.klass}).to` instead."
          )
        end

        def setup_mock_proxy_method_substitute(subject, method, block)
          proxy = ::RSpec::Mocks.space.proxy_for(subject)
          setup_method_substitute(proxy, method, block)
        end

        def setup_any_instance_method_substitute(subject, method, block)
          proxy = ::RSpec::Mocks.space.any_instance_proxy_for(subject)
          setup_method_substitute(proxy, method, block)
        end

        def setup_method_substitute(host, method, block, *args)
          args << @message.to_sym
          block = move_block_to_last_customization(block)

          expectation = host.__send__(method, *args, &(@block || block))

          @recorded_customizations.each do |customization|
            customization.playback_onto(expectation)
          end
          expectation
        end

        def move_block_to_last_customization(block)
          last = @recorded_customizations.last
          return block unless last

          last.block ||= block
          nil
        end

        # MessageExpectation objects are able to describe themselves in detail.
        # We use this as a fall back when a MessageExpectation is not available.
        # @private
        class DefaultDescribable
          def initialize(message)
            @message = message
          end

          # This is much simpler for the `any_instance` case than what the
          # user may want, but I'm not up for putting a bunch of effort
          # into full descriptions for `any_instance` expectations at this point :(.
          def description_for(verb)
            "#{verb} #{@message}"
          end
        end
      end
    end
  end
end
