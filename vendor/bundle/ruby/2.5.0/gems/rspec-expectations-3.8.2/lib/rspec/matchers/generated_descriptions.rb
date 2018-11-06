module RSpec
  module Matchers
    class << self
      # @private
      attr_accessor :last_matcher, :last_expectation_handler
    end

    # @api private
    # Used by rspec-core to clear the state used to generate
    # descriptions after an example.
    def self.clear_generated_description
      self.last_matcher = nil
      self.last_expectation_handler = nil
    end

    # @api private
    # Generates an an example description based on the last expectation.
    # Used by rspec-core's one-liner syntax.
    def self.generated_description
      return nil if last_expectation_handler.nil?
      "#{last_expectation_handler.verb} #{last_description}"
    end

    # @private
    def self.last_description
      last_matcher.respond_to?(:description) ? last_matcher.description : <<-MESSAGE
When you call a matcher in an example without a String, like this:

specify { expect(object).to matcher }

or this:

it { is_expected.to matcher }

RSpec expects the matcher to have a #description method. You should either
add a String to the example this matcher is being used in, or give it a
description method. Then you won't have to suffer this lengthy warning again.
MESSAGE
    end
  end
end
