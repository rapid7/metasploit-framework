module RSpec
  module Mocks
    module AnyInstance
      # @private
      class ErrorGenerator < ::RSpec::Mocks::ErrorGenerator
        def raise_second_instance_received_message_error(unfulfilled_expectations)
          __raise "Exactly one instance should have received the following " \
                  "message(s) but didn't: #{unfulfilled_expectations.sort.join(', ')}"
        end

        def raise_does_not_implement_error(klass, method_name)
          __raise "#{klass} does not implement ##{method_name}"
        end

        def raise_message_already_received_by_other_instance_error(method_name, object_inspect, invoked_instance)
          __raise "The message '#{method_name}' was received by #{object_inspect} " \
                  "but has already been received by #{invoked_instance}"
        end

        def raise_not_supported_with_prepend_error(method_name, problem_mod)
          __raise "Using `any_instance` to stub a method (#{method_name}) that has been " \
                  "defined on a prepended module (#{problem_mod}) is not supported."
        end
      end

      def self.error_generator
        @error_generator ||= ErrorGenerator.new
      end
    end
  end
end
