require "rspec/support/warnings"

module RSpec
  module Core
    # @private
    module Warnings
      # @private
      #
      # Used internally to print deprecation warnings.
      def deprecate(deprecated, data={})
        RSpec.configuration.reporter.deprecation(
          {
            :deprecated => deprecated,
            :call_site => CallerFilter.first_non_rspec_line
          }.merge(data)
        )
      end

      # @private
      #
      # Used internally to print deprecation warnings.
      def warn_deprecation(message, opts={})
        RSpec.configuration.reporter.deprecation opts.merge(:message => message)
      end

      # @private
      def warn_with(message, options={})
        if options[:use_spec_location_as_call_site]
          message += "." unless message.end_with?(".")

          if RSpec.current_example
            message += " Warning generated from spec at `#{RSpec.current_example.location}`."
          end
        end

        super(message, options)
      end
    end
  end
end
