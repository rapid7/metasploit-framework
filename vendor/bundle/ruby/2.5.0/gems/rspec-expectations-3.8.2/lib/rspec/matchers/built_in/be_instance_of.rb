module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `be_an_instance_of`.
      # Not intended to be instantiated directly.
      class BeAnInstanceOf < BaseMatcher
        # @api private
        # @return [String]
        def description
          "be an instance of #{expected}"
        end

      private

        def match(expected, actual)
          actual.instance_of? expected
        end
      end
    end
  end
end
