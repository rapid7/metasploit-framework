RSpec::Support.require_rspec_core "formatters/base_text_formatter"
RSpec::Support.require_rspec_core "formatters/console_codes"

module RSpec
  module Core
    module Formatters
      # @private
      class ProgressFormatter < BaseTextFormatter
        Formatters.register self, :example_passed, :example_pending, :example_failed, :start_dump

        def example_passed(_notification)
          output.print ConsoleCodes.wrap('.', :success)
        end

        def example_pending(_notification)
          output.print ConsoleCodes.wrap('*', :pending)
        end

        def example_failed(_notification)
          output.print ConsoleCodes.wrap('F', :failure)
        end

        def start_dump(_notification)
          output.puts
        end
      end
    end
  end
end
