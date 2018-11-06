RSpec::Support.require_rspec_support "object_formatter"

module RSpec
  module Mocks
    # Raised when a message expectation is not satisfied.
    MockExpectationError = Class.new(Exception)

    # Raised when a test double is used after it has been torn
    # down (typically at the end of an rspec-core example).
    ExpiredTestDoubleError = Class.new(MockExpectationError)

    # Raised when doubles or partial doubles are used outside of the per-test lifecycle.
    OutsideOfExampleError = Class.new(StandardError)

    # Raised when an expectation customization method (e.g. `with`,
    # `and_return`) is called on a message expectation which has already been
    # invoked.
    MockExpectationAlreadyInvokedError = Class.new(Exception)

    # Raised for situations that RSpec cannot support due to mutations made
    # externally on arguments that RSpec is holding onto to use for later
    # comparisons.
    #
    # @deprecated We no longer raise this error but the constant remains until
    #   RSpec 4 for SemVer reasons.
    CannotSupportArgMutationsError = Class.new(StandardError)

    # @private
    UnsupportedMatcherError  = Class.new(StandardError)
    # @private
    NegationUnsupportedError = Class.new(StandardError)
    # @private
    VerifyingDoubleNotDefinedError = Class.new(StandardError)

    # @private
    class ErrorGenerator
      attr_writer :opts

      def initialize(target=nil)
        @target = target
      end

      # @private
      def opts
        @opts ||= {}
      end

      # @private
      def raise_unexpected_message_error(message, args)
        __raise "#{intro} received unexpected message :#{message} with #{format_args(args)}"
      end

      # @private
      def raise_unexpected_message_args_error(expectation, args_for_multiple_calls, source_id=nil)
        __raise error_message(expectation, args_for_multiple_calls), nil, source_id
      end

      # @private
      def raise_missing_default_stub_error(expectation, args_for_multiple_calls)
        __raise(
          error_message(expectation, args_for_multiple_calls) +
          "\n Please stub a default value first if message might be received with other args as well. \n"
        )
      end

      # @private
      def raise_similar_message_args_error(expectation, args_for_multiple_calls, backtrace_line=nil)
        __raise error_message(expectation, args_for_multiple_calls), backtrace_line
      end

      def default_error_message(expectation, expected_args, actual_args)
        "#{intro} received #{expectation.message.inspect} #{unexpected_arguments_message(expected_args, actual_args)}".dup
      end

      # rubocop:disable Metrics/ParameterLists
      # @private
      def raise_expectation_error(message, expected_received_count, argument_list_matcher,
                                  actual_received_count, expectation_count_type, args,
                                  backtrace_line=nil, source_id=nil)
        expected_part = expected_part_of_expectation_error(expected_received_count, expectation_count_type, argument_list_matcher)
        received_part = received_part_of_expectation_error(actual_received_count, args)
        __raise "(#{intro(:unwrapped)}).#{message}#{format_args(args)}\n    #{expected_part}\n    #{received_part}", backtrace_line, source_id
      end
      # rubocop:enable Metrics/ParameterLists

      # @private
      def raise_unimplemented_error(doubled_module, method_name, object)
        message = case object
                  when InstanceVerifyingDouble
                    "the %s class does not implement the instance method: %s".dup <<
                      if ObjectMethodReference.for(doubled_module, method_name).implemented?
                        ". Perhaps you meant to use `class_double` instead?"
                      else
                        ""
                      end
                  when ClassVerifyingDouble
                    "the %s class does not implement the class method: %s".dup <<
                      if InstanceMethodReference.for(doubled_module, method_name).implemented?
                        ". Perhaps you meant to use `instance_double` instead?"
                      else
                        ""
                      end
                  else
                    "%s does not implement: %s"
                  end

        __raise message % [doubled_module.description, method_name]
      end

      # @private
      def raise_non_public_error(method_name, visibility)
        raise NoMethodError, "%s method `%s' called on %s" % [
          visibility, method_name, intro
        ]
      end

      # @private
      def raise_invalid_arguments_error(verifier)
        __raise verifier.error_message
      end

      # @private
      def raise_expired_test_double_error
        raise ExpiredTestDoubleError,
              "#{intro} was originally created in one example but has leaked into " \
              "another example and can no longer be used. rspec-mocks' doubles are " \
              "designed to only last for one example, and you need to create a new " \
              "one in each example you wish to use it for."
      end

      # @private
      def describe_expectation(verb, message, expected_received_count, _actual_received_count, args)
        "#{verb} #{message}#{format_args(args)} #{count_message(expected_received_count)}"
      end

      # @private
      def raise_out_of_order_error(message)
        __raise "#{intro} received :#{message} out of order"
      end

      # @private
      def raise_missing_block_error(args_to_yield)
        __raise "#{intro} asked to yield |#{arg_list(args_to_yield)}| but no block was passed"
      end

      # @private
      def raise_wrong_arity_error(args_to_yield, signature)
        __raise "#{intro} yielded |#{arg_list(args_to_yield)}| to block with #{signature.description}"
      end

      # @private
      def raise_only_valid_on_a_partial_double(method)
        __raise "#{intro} is a pure test double. `#{method}` is only " \
                "available on a partial double."
      end

      # @private
      def raise_expectation_on_unstubbed_method(method)
        __raise "#{intro} expected to have received #{method}, but that " \
                "object is not a spy or method has not been stubbed."
      end

      # @private
      def raise_expectation_on_mocked_method(method)
        __raise "#{intro} expected to have received #{method}, but that " \
                "method has been mocked instead of stubbed or spied."
      end

      # @private
      def raise_double_negation_error(wrapped_expression)
        __raise "Isn't life confusing enough? You've already set a " \
                "negative message expectation and now you are trying to " \
                "negate it again with `never`. What does an expression like " \
                "`#{wrapped_expression}.not_to receive(:msg).never` even mean?"
      end

      # @private
      def raise_verifying_double_not_defined_error(ref)
        notify(VerifyingDoubleNotDefinedError.new(
          "#{ref.description.inspect} is not a defined constant. " \
          "Perhaps you misspelt it? " \
          "Disable check with `verify_doubled_constant_names` configuration option."
        ))
      end

      # @private
      def raise_have_received_disallowed(type, reason)
        __raise "Using #{type}(...) with the `have_received` " \
                "matcher is not supported#{reason}."
      end

      # @private
      def raise_cant_constrain_count_for_negated_have_received_error(count_constraint)
        __raise "can't use #{count_constraint} when negative"
      end

      # @private
      def raise_method_not_stubbed_error(method_name)
        __raise "The method `#{method_name}` was not stubbed or was already unstubbed"
      end

      # @private
      def raise_already_invoked_error(message, calling_customization)
        error_message = "The message expectation for #{intro}.#{message} has already been invoked " \
          "and cannot be modified further (e.g. using `#{calling_customization}`). All message expectation " \
          "customizations must be applied before it is used for the first time."

        notify MockExpectationAlreadyInvokedError.new(error_message)
      end

      def raise_expectation_on_nil_error(method_name)
        __raise expectation_on_nil_message(method_name)
      end

      def expectation_on_nil_message(method_name)
        "An expectation of `:#{method_name}` was set on `nil`. " \
        "To allow expectations on `nil` and suppress this message, set `RSpec::Mocks.configuration.allow_message_expectations_on_nil` to `true`. " \
        "To disallow expectations on `nil`, set `RSpec::Mocks.configuration.allow_message_expectations_on_nil` to `false`"
      end

      # @private
      def intro(unwrapped=false)
        case @target
        when TestDouble then TestDoubleFormatter.format(@target, unwrapped)
        when Class then
          formatted = "#{@target.inspect} (class)"
          return formatted if unwrapped
          "#<#{formatted}>"
        when NilClass then "nil"
        else @target.inspect
        end
      end

      # @private
      def method_call_args_description(args, generic_prefix=" with arguments: ", matcher_prefix=" with ")
        case args.first
        when ArgumentMatchers::AnyArgsMatcher then "#{matcher_prefix}any arguments"
        when ArgumentMatchers::NoArgsMatcher  then "#{matcher_prefix}no arguments"
        else
          if yield
            "#{generic_prefix}#{format_args(args)}"
          else
            ""
          end
        end
      end

    private

      def received_part_of_expectation_error(actual_received_count, args)
        "received: #{count_message(actual_received_count)}" +
          method_call_args_description(args) do
            actual_received_count > 0 && args.length > 0
          end
      end

      def expected_part_of_expectation_error(expected_received_count, expectation_count_type, argument_list_matcher)
        "expected: #{count_message(expected_received_count, expectation_count_type)}" +
          method_call_args_description(argument_list_matcher.expected_args) do
            argument_list_matcher.expected_args.length > 0
          end
      end

      def unexpected_arguments_message(expected_args_string, actual_args_string)
        "with unexpected arguments\n  expected: #{expected_args_string}\n       got: #{actual_args_string}"
      end

      def error_message(expectation, args_for_multiple_calls)
        expected_args = format_args(expectation.expected_args)
        actual_args = format_received_args(args_for_multiple_calls)
        message = default_error_message(expectation, expected_args, actual_args)

        if args_for_multiple_calls.one?
          diff = diff_message(expectation.expected_args, args_for_multiple_calls.first)
          message << "\nDiff:#{diff}" unless diff.strip.empty?
        end

        message
      end

      def diff_message(expected_args, actual_args)
        formatted_expected_args = expected_args.map do |x|
          RSpec::Support.rspec_description_for_object(x)
        end

        formatted_expected_args, actual_args = unpack_string_args(formatted_expected_args, actual_args)

        differ.diff(actual_args, formatted_expected_args)
      end

      def unpack_string_args(formatted_expected_args, actual_args)
        if [formatted_expected_args, actual_args].all? { |x| list_of_exactly_one_string?(x) }
          [formatted_expected_args.first, actual_args.first]
        else
          [formatted_expected_args, actual_args]
        end
      end

      def list_of_exactly_one_string?(args)
        Array === args && args.count == 1 && String === args.first
      end

      def differ
        RSpec::Support::Differ.new(:color => RSpec::Mocks.configuration.color?)
      end

      def __raise(message, backtrace_line=nil, source_id=nil)
        message = opts[:message] unless opts[:message].nil?
        exception = RSpec::Mocks::MockExpectationError.new(message)
        prepend_to_backtrace(exception, backtrace_line) if backtrace_line
        notify exception, :source_id => source_id
      end

      if RSpec::Support::Ruby.jruby?
        def prepend_to_backtrace(exception, line)
          raise exception
        rescue RSpec::Mocks::MockExpectationError => with_backtrace
          with_backtrace.backtrace.unshift(line)
        end
      else
        def prepend_to_backtrace(exception, line)
          exception.set_backtrace(caller.unshift line)
        end
      end

      def notify(*args)
        RSpec::Support.notify_failure(*args)
      end

      def format_args(args)
        return "(no args)" if args.empty?
        "(#{arg_list(args)})"
      end

      def arg_list(args)
        args.map { |arg| RSpec::Support::ObjectFormatter.format(arg) }.join(", ")
      end

      def format_received_args(args_for_multiple_calls)
        grouped_args(args_for_multiple_calls).map do |args_for_one_call, index|
          "#{format_args(args_for_one_call)}#{group_count(index, args_for_multiple_calls)}"
        end.join("\n            ")
      end

      def count_message(count, expectation_count_type=nil)
        return "at least #{times(count.abs)}" if count < 0 || expectation_count_type == :at_least
        return "at most #{times(count)}" if expectation_count_type == :at_most
        times(count)
      end

      def times(count)
        "#{count} time#{count == 1 ? '' : 's'}"
      end

      def grouped_args(args)
        Hash[args.group_by { |x| x }.map { |k, v| [k, v.count] }]
      end

      def group_count(index, args)
        " (#{times(index)})" if args.size > 1 || index > 1
      end
    end

    # @private
    def self.error_generator
      @error_generator ||= ErrorGenerator.new
    end
  end
end
