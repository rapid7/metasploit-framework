require 'spec/runner/formatter/progress_bar_formatter'

module Fivemat
  class Spec < ::Spec::Runner::Formatter::ProgressBarFormatter
    include ElapsedTime

    def initialize(*)
      super
      @dumping = false
      @example_group_number = 0
      @failed_examples = []
      @failure_index_offset = 1
      @last_nested_descriptions = []
      @last_root_example_group = nil
    end

    def example_group_started(example_group_proxy)
      super
      @example_group_number += 1

      unless example_group_proxy.nested_descriptions.first == @last_nested_descriptions.first
        @last_root_example_group = example_group_proxy
        example_group_finished(example_group_proxy) unless @example_group_number == 1
        output.print "#{example_group_proxy.nested_descriptions.first} "
        @start_time = Time.now
      end

      @last_nested_descriptions = example_group_proxy.nested_descriptions
    end

    def example_group_finished(example_group_proxy)
      print_elapsed_time output, @start_time
      puts

      @failed_examples.each_with_index do |example, index|
        dump_failure(@failure_index_offset + index, example)
      end

      @failure_index_offset += @failed_examples.size
      @failed_examples.clear
    end

    def example_failed(example, counter, failure)
      super
      @failed_examples << failure
    end

    def start_dump
      example_group_finished(@last_root_example_group)
      @dumping = true
    end

    def dump_failure(*)
      super unless @dumping
    end
  end
end
