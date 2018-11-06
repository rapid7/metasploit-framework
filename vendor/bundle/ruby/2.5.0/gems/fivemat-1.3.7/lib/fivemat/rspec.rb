require 'rspec/core/formatters/progress_formatter'

module Fivemat
  class RSpec < ::RSpec::Core::Formatters::ProgressFormatter
    include ElapsedTime

    def initialize(*)
      super
      @group_level = 0
      @index_offset = 0
      @cumulative_failed_examples = []
    end

    def example_group_started(group)
      if @group_level.zero?
        output.print "#{group.description} "
        @failure_output = []
        @start_time = Time.now
      end
      @group_level += 1
    end

    def example_group_finished(group)
      @group_level -= 1
      if @group_level.zero?
        print_elapsed_time output, @start_time
        output.puts

        failed_examples.each_with_index do |example, index|
          if pending_fixed?(example)
            dump_pending_fixed(example, @index_offset + index)
          else
            dump_failure(example, @index_offset + index)
          end
          dump_backtrace(example)
        end
        @index_offset += failed_examples.size
        @cumulative_failed_examples += failed_examples
        failed_examples.clear
      end
    end

    def pending_fixed?(example)
      if example.execution_result[:exception].respond_to?(:pending_fixed?)
        example.execution_result[:exception].pending_fixed?
      elsif defined?(::RSpec::Core::Pending::PendingExampleFixedError)
        # RSpec 2.99.2 compatibility
        ::RSpec::Core::Pending::PendingExampleFixedError == example.execution_result[:exception]
      else
        ::RSpec::Core::PendingExampleFixedError === example.execution_result[:exception]
      end
    end

    def dump_pending_fixed(example, index)
      output.puts "#{short_padding}#{index.next}) #{example.full_description} FIXED"
      output.puts blue("#{long_padding}Expected pending '#{example.metadata[:execution_result][:pending_message]}' to fail. No Error was raised.")
    end

    def dump_summary(*)
      @failed_examples = @cumulative_failed_examples
      super
    end

    def start_dump
      # Skip the call to output.puts in the messiest way possible.
      self.class.superclass.superclass.instance_method(:start_dump).bind(self).call
    end
  end
end
