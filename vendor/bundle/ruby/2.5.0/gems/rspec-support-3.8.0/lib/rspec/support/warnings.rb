require 'rspec/support'
RSpec::Support.require_rspec_support "caller_filter"

module RSpec
  module Support
    module Warnings
      def deprecate(deprecated, options={})
        warn_with "DEPRECATION: #{deprecated} is deprecated.", options
      end

      # @private
      #
      # Used internally to print deprecation warnings
      # when rspec-core isn't loaded
      def warn_deprecation(message, options={})
        warn_with "DEPRECATION: \n #{message}", options
      end

      # @private
      #
      # Used internally to print warnings
      def warning(text, options={})
        warn_with "WARNING: #{text}.", options
      end

      # @private
      #
      # Used internally to print longer warnings
      def warn_with(message, options={})
        call_site = options.fetch(:call_site) { CallerFilter.first_non_rspec_line }
        message += " Use #{options[:replacement]} instead." if options[:replacement]
        message += " Called from #{call_site}." if call_site
        Support.warning_notifier.call message
      end
    end
  end

  extend RSpec::Support::Warnings
end
