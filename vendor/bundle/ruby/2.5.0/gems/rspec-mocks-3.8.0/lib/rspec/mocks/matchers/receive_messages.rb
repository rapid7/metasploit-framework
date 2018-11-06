module RSpec
  module Mocks
    module Matchers
      # @private
      class ReceiveMessages
        include Matcher

        def initialize(message_return_value_hash)
          @message_return_value_hash = message_return_value_hash
          @backtrace_line = CallerFilter.first_non_rspec_line
        end

        def name
          "receive_messages"
        end

        def description
          "receive messages: #{@message_return_value_hash.inspect}"
        end

        def setup_expectation(subject)
          warn_about_block if block_given?
          each_message_on(proxy_on(subject)) do |host, message, return_value|
            host.add_simple_expectation(message, return_value, @backtrace_line)
          end
        end
        alias matches? setup_expectation

        def setup_negative_expectation(_subject)
          raise NegationUnsupportedError,
                "`expect(...).to_not receive_messages` is not supported since it " \
                "doesn't really make sense. What would it even mean?"
        end
        alias does_not_match? setup_negative_expectation

        def setup_allowance(subject)
          warn_about_block if block_given?
          each_message_on(proxy_on(subject)) do |host, message, return_value|
            host.add_simple_stub(message, return_value)
          end
        end

        def setup_any_instance_expectation(subject)
          warn_about_block if block_given?
          each_message_on(any_instance_of(subject)) do |host, message, return_value|
            host.should_receive(message).and_return(return_value)
          end
        end

        def setup_any_instance_allowance(subject)
          warn_about_block if block_given?
          any_instance_of(subject).stub(@message_return_value_hash)
        end

        def warn_about_block
          raise "Implementation blocks aren't supported with `receive_messages`"
        end

      private

        def proxy_on(subject)
          ::RSpec::Mocks.space.proxy_for(subject)
        end

        def any_instance_of(subject)
          ::RSpec::Mocks.space.any_instance_proxy_for(subject)
        end

        def each_message_on(host)
          @message_return_value_hash.each do |message, value|
            yield host, message, value
          end
        end
      end
    end
  end
end
