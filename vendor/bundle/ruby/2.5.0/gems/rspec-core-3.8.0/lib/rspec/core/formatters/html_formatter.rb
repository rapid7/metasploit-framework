RSpec::Support.require_rspec_core "formatters/base_text_formatter"
RSpec::Support.require_rspec_core "formatters/html_printer"

module RSpec
  module Core
    module Formatters
      # @private
      class HtmlFormatter < BaseFormatter
        Formatters.register self, :start, :example_group_started, :start_dump,
                            :example_started, :example_passed, :example_failed,
                            :example_pending, :dump_summary

        def initialize(output)
          super(output)
          @failed_examples = []
          @example_group_number = 0
          @example_number = 0
          @header_red = nil
          @printer = HtmlPrinter.new(output)
        end

        def start(notification)
          super
          @printer.print_html_start
          @printer.flush
        end

        def example_group_started(notification)
          super
          @example_group_red = false
          @example_group_number += 1

          @printer.print_example_group_end unless example_group_number == 1
          @printer.print_example_group_start(example_group_number,
                                             notification.group.description,
                                             notification.group.parent_groups.size)
          @printer.flush
        end

        def start_dump(_notification)
          @printer.print_example_group_end
          @printer.flush
        end

        def example_started(_notification)
          @example_number += 1
        end

        def example_passed(passed)
          @printer.move_progress(percent_done)
          @printer.print_example_passed(passed.example.description, passed.example.execution_result.run_time)
          @printer.flush
        end

        def example_failed(failure)
          @failed_examples << failure.example
          unless @header_red
            @header_red = true
            @printer.make_header_red
          end

          unless @example_group_red
            @example_group_red = true
            @printer.make_example_group_header_red(example_group_number)
          end

          @printer.move_progress(percent_done)

          example = failure.example

          exception = failure.exception
          message_lines = failure.fully_formatted_lines(nil, RSpec::Core::Notifications::NullColorizer)
          exception_details = if exception
                                {
                                  # drop 2 removes the description (regardless of newlines) and leading blank line
                                  :message => message_lines.drop(2).join("\n"),
                                  :backtrace => failure.formatted_backtrace.join("\n"),
                                }
                              end
          extra = extra_failure_content(failure)

          @printer.print_example_failed(
            example.execution_result.pending_fixed,
            example.description,
            example.execution_result.run_time,
            @failed_examples.size,
            exception_details,
            (extra == "") ? false : extra
          )
          @printer.flush
        end

        def example_pending(pending)
          example = pending.example

          @printer.make_header_yellow unless @header_red
          @printer.make_example_group_header_yellow(example_group_number) unless @example_group_red
          @printer.move_progress(percent_done)
          @printer.print_example_pending(example.description, example.execution_result.pending_message)
          @printer.flush
        end

        def dump_summary(summary)
          @printer.print_summary(
            summary.duration,
            summary.example_count,
            summary.failure_count,
            summary.pending_count
          )
          @printer.flush
        end

      private

        # If these methods are declared with attr_reader Ruby will issue a
        # warning because they are private.
        # rubocop:disable Style/TrivialAccessors

        # The number of the currently running example_group.
        def example_group_number
          @example_group_number
        end

        # The number of the currently running example (a global counter).
        def example_number
          @example_number
        end
        # rubocop:enable Style/TrivialAccessors

        def percent_done
          result = 100.0
          if @example_count > 0
            result = (((example_number).to_f / @example_count.to_f * 1000).to_i / 10.0).to_f
          end
          result
        end

        # Override this method if you wish to output extra HTML for a failed
        # spec. For example, you could output links to images or other files
        # produced during the specs.
        def extra_failure_content(failure)
          RSpec::Support.require_rspec_core "formatters/html_snippet_extractor"
          backtrace = (failure.exception.backtrace || []).map do |line|
            RSpec.configuration.backtrace_formatter.backtrace_line(line)
          end
          backtrace.compact!
          @snippet_extractor ||= HtmlSnippetExtractor.new
          "    <pre class=\"ruby\"><code>#{@snippet_extractor.snippet(backtrace)}</code></pre>"
        end
      end
    end
  end
end
