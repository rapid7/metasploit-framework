module RSpec
  module Expectations
    # @private
    class FailureAggregator
      attr_reader :block_label, :metadata

      def aggregate
        RSpec::Support.with_failure_notifier(self) do
          begin
            yield
          rescue ExpectationNotMetError => e
            # Normally, expectation failures will be notified via the `call` method, below,
            # but since the failure notifier uses a thread local variable, failing expectations
            # in another thread will still raise. We handle that here and categorize it as part
            # of `failures` rather than letting it fall through and be categorized as part of
            # `other_errors`.
            failures << e
          rescue Support::AllExceptionsExceptOnesWeMustNotRescue => e
            # While it is normally a bad practice to rescue `Exception`, it's important we do
            # so here. It's low risk (`notify_aggregated_failures` below will re-raise the exception,
            # or raise a `MultipleExpectationsNotMetError` that includes the exception), and it's
            # essential that the user is notified of expectation failures that may have already
            # occurred in the `aggregate_failures` block. Those expectation failures may provide
            # important diagnostics for understanding why this exception occurred, and if we simply
            # allowed this exception to be raised as-is, it would (wrongly) suggest to the user
            # that the expectation passed when it did not, which would be quite confusing.
            other_errors << e
          end
        end

        notify_aggregated_failures
      end

      def failures
        @failures ||= []
      end

      def other_errors
        @other_errors ||= []
      end

      # This method is defined to satisfy the callable interface
      # expected by `RSpec::Support.with_failure_notifier`.
      def call(failure, options)
        source_id = options[:source_id]
        return if source_id && @seen_source_ids.key?(source_id)

        @seen_source_ids[source_id] = true
        assign_backtrace(failure) unless failure.backtrace
        failures << failure
      end

    private

      if RSpec::Support::Ruby.jruby?
        # On JRuby, `caller` and `raise` produce different backtraces with regards to `.java`
        # stack frames. It's important that we use `raise` for JRuby to produce a backtrace
        # that has a continuous common section with the raised `MultipleExpectationsNotMetError`,
        # so that rspec-core's truncation logic can work properly on it to list the backtrace
        # relative to the `aggregate_failures` block.
        def assign_backtrace(failure)
          raise failure
        rescue failure.class => e
          failure.set_backtrace(e.backtrace)
        end
      else
        # Using `caller` performs better (and is simpler) than `raise` on most Rubies.
        def assign_backtrace(failure)
          failure.set_backtrace(caller)
        end
      end

      def initialize(block_label, metadata)
        @block_label     = block_label
        @metadata        = metadata
        @seen_source_ids = {} # don't want to load stdlib set
      end

      def notify_aggregated_failures
        all_errors = failures + other_errors

        case all_errors.size
        when 0 then return nil
        when 1 then RSpec::Support.notify_failure all_errors.first
        else RSpec::Support.notify_failure MultipleExpectationsNotMetError.new(self)
        end
      end
    end

    # Exception raised from `aggregate_failures` when multiple expectations fail.
    class MultipleExpectationsNotMetError
      # @return [String] The fully formatted exception message.
      def message
        @message ||= (["#{summary}:"] + enumerated_failures + enumerated_errors).join("\n\n")
      end

      # @return [Array<RSpec::Expectations::ExpectationNotMetError>] The list of expectation failures.
      def failures
        @failure_aggregator.failures
      end

      # @return [Array<Exception>] The list of other exceptions.
      def other_errors
        @failure_aggregator.other_errors
      end

      # @return [Array<Exception>] The list of expectation failures and other exceptions, combined.
      attr_reader :all_exceptions

      # @return [String] The user-assigned label for the aggregation block.
      def aggregation_block_label
        @failure_aggregator.block_label
      end

      # @return [Hash] The metadata hash passed to `aggregate_failures`.
      def aggregation_metadata
        @failure_aggregator.metadata
      end

      # @return [String] A summary of the failure, including the block label and a count of failures.
      def summary
        "Got #{exception_count_description} from failure aggregation " \
        "block#{block_description}"
      end

      # return [String] A description of the failure/error counts.
      def exception_count_description
        failure_count = pluralize("failure", failures.size)
        return failure_count if other_errors.empty?
        error_count = pluralize("other error", other_errors.size)
        "#{failure_count} and #{error_count}"
      end

    private

      def initialize(failure_aggregator)
        @failure_aggregator = failure_aggregator
        @all_exceptions = failures + other_errors
      end

      def block_description
        return "" unless aggregation_block_label
        " #{aggregation_block_label.inspect}"
      end

      def pluralize(noun, count)
        "#{count} #{noun}#{'s' unless count == 1}"
      end

      def enumerated(exceptions, index_offset)
        exceptions.each_with_index.map do |exception, index|
          index += index_offset
          formatted_message = yield exception
          "#{index_label index}#{indented formatted_message, index}"
        end
      end

      def enumerated_failures
        enumerated(failures, 0, &:message)
      end

      def enumerated_errors
        enumerated(other_errors, failures.size) do |error|
          "#{error.class}: #{error.message}"
        end
      end

      def indented(failure_message, index)
        line_1, *rest = failure_message.strip.lines.to_a
        first_line_indentation = ' ' * (longest_index_label_width - width_of_label(index))

        first_line_indentation + line_1 + rest.map do |line|
          line =~ /\S/ ? indentation + line : line
        end.join
      end

      def indentation
        @indentation ||= ' ' * longest_index_label_width
      end

      def longest_index_label_width
        @longest_index_label_width ||= width_of_label(failures.size)
      end

      def width_of_label(index)
        index_label(index).chars.count
      end

      def index_label(index)
        "  #{index + 1}) "
      end
    end
  end
end
