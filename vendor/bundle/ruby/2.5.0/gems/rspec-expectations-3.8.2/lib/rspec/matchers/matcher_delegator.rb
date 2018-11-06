module RSpec
  module Matchers
    # Provides the necessary plumbing to wrap a matcher with a decorator.
    # @private
    class MatcherDelegator
      include Composable
      attr_reader :base_matcher

      def initialize(base_matcher)
        @base_matcher = base_matcher
      end

      def method_missing(*args, &block)
        base_matcher.__send__(*args, &block)
      end

      if ::RUBY_VERSION.to_f > 1.8
        def respond_to_missing?(name, include_all=false)
          super || base_matcher.respond_to?(name, include_all)
        end
      else
        # :nocov:
        def respond_to?(name, include_all=false)
          super || base_matcher.respond_to?(name, include_all)
        end
        # :nocov:
      end

      def initialize_copy(other)
        @base_matcher = @base_matcher.clone
        super
      end
    end
  end
end
