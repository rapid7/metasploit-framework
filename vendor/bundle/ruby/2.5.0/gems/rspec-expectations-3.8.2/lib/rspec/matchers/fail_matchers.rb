require 'rspec/expectations'

module RSpec
  module Matchers
    # Matchers for testing RSpec matchers. Include them with:
    #
    #     require 'rspec/matchers/fail_matchers'
    #     RSpec.configure do |config|
    #       config.include RSpec::Matchers::FailMatchers
    #     end
    #
    module FailMatchers
      # Matches if an expectation fails
      #
      # @example
      #   expect { some_expectation }.to fail
      def fail(&block)
        raise_error(RSpec::Expectations::ExpectationNotMetError, &block)
      end

      # Matches if an expectation fails with the provided message
      #
      # @example
      #   expect { some_expectation }.to fail_with("some failure message")
      #   expect { some_expectation }.to fail_with(/some failure message/)
      def fail_with(message)
        raise_error(RSpec::Expectations::ExpectationNotMetError, message)
      end

      # Matches if an expectation fails including the provided message
      #
      # @example
      #   expect { some_expectation }.to fail_including("portion of some failure message")
      def fail_including(*snippets)
        raise_error(
          RSpec::Expectations::ExpectationNotMetError,
          a_string_including(*snippets)
        )
      end
    end
  end
end
