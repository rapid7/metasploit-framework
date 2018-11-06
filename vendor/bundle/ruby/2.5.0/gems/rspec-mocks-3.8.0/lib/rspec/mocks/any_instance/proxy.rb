module RSpec
  module Mocks
    module AnyInstance
      # @private
      # The `AnyInstance::Recorder` is responsible for redefining the klass's
      # instance method in order to add any stubs/expectations the first time
      # the method is called. It's not capable of updating a stub on an instance
      # that's already been previously stubbed (either directly, or via
      # `any_instance`).
      #
      # This proxy sits in front of the recorder and delegates both to it
      # and to the `RSpec::Mocks::Proxy` for each already mocked or stubbed
      # instance of the class, in order to propogates changes to the instances.
      #
      # Note that unlike `RSpec::Mocks::Proxy`, this proxy class is stateless
      # and is not persisted in `RSpec::Mocks.space`.
      #
      # Proxying for the message expectation fluent interface (typically chained
      # off of the return value of one of these methods) is provided by the
      # `FluentInterfaceProxy` class below.
      class Proxy
        def initialize(recorder, target_proxies)
          @recorder       = recorder
          @target_proxies = target_proxies
        end

        def klass
          @recorder.klass
        end

        def stub(method_name_or_method_map, &block)
          if Hash === method_name_or_method_map
            method_name_or_method_map.each do |method_name, return_value|
              stub(method_name).and_return(return_value)
            end
          else
            perform_proxying(__method__, [method_name_or_method_map], block) do |proxy|
              proxy.add_stub(method_name_or_method_map, &block)
            end
          end
        end

        def unstub(method_name)
          perform_proxying(__method__, [method_name], nil) do |proxy|
            proxy.remove_stub_if_present(method_name)
          end
        end

        def stub_chain(*chain, &block)
          perform_proxying(__method__, chain, block) do |proxy|
            Mocks::StubChain.stub_chain_on(proxy.object, *chain, &block)
          end
        end

        def expect_chain(*chain, &block)
          perform_proxying(__method__, chain, block) do |proxy|
            Mocks::ExpectChain.expect_chain_on(proxy.object, *chain, &block)
          end
        end

        def should_receive(method_name, &block)
          perform_proxying(__method__, [method_name], block) do |proxy|
            # Yeah, this is a bit odd...but if we used `add_message_expectation`
            # then it would act like `expect_every_instance_of(klass).to receive`.
            # The any_instance recorder takes care of validating that an instance
            # received the message.
            proxy.add_stub(method_name, &block)
          end
        end

        def should_not_receive(method_name, &block)
          perform_proxying(__method__, [method_name], block) do |proxy|
            proxy.add_message_expectation(method_name, &block).never
          end
        end

      private

        def perform_proxying(method_name, args, block, &target_proxy_block)
          recorder_value = @recorder.__send__(method_name, *args, &block)
          proxy_values   = @target_proxies.map(&target_proxy_block)
          FluentInterfaceProxy.new([recorder_value] + proxy_values)
        end
      end

      # @private
      # Delegates messages to each of the given targets in order to
      # provide the fluent interface that is available off of message
      # expectations when dealing with `any_instance`.
      #
      # `targets` will typically contain 1 of the `AnyInstance::Recorder`
      # return values and N `MessageExpectation` instances (one per instance
      # of the `any_instance` klass).
      class FluentInterfaceProxy
        def initialize(targets)
          @targets = targets
        end

        if RUBY_VERSION.to_f > 1.8
          def respond_to_missing?(method_name, include_private=false)
            super || @targets.first.respond_to?(method_name, include_private)
          end
        else
          def respond_to?(method_name, include_private=false)
            super || @targets.first.respond_to?(method_name, include_private)
          end
        end

        def method_missing(*args, &block)
          return_values = @targets.map { |t| t.__send__(*args, &block) }
          FluentInterfaceProxy.new(return_values)
        end
      end
    end
  end
end
