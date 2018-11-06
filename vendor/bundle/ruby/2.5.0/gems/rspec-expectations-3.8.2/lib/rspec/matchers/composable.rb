RSpec::Support.require_rspec_support "fuzzy_matcher"

module RSpec
  module Matchers
    # Mixin designed to support the composable matcher features
    # of RSpec 3+. Mix it into your custom matcher classes to
    # allow them to be used in a composable fashion.
    #
    # @api public
    module Composable
      # Creates a compound `and` expectation. The matcher will
      # only pass if both sub-matchers pass.
      # This can be chained together to form an arbitrarily long
      # chain of matchers.
      #
      # @example
      #   expect(alphabet).to start_with("a").and end_with("z")
      #   expect(alphabet).to start_with("a") & end_with("z")
      #
      # @note The negative form (`expect(...).not_to matcher.and other`)
      #   is not supported at this time.
      def and(matcher)
        BuiltIn::Compound::And.new self, matcher
      end
      alias & and

      # Creates a compound `or` expectation. The matcher will
      # pass if either sub-matcher passes.
      # This can be chained together to form an arbitrarily long
      # chain of matchers.
      #
      # @example
      #   expect(stoplight.color).to eq("red").or eq("green").or eq("yellow")
      #   expect(stoplight.color).to eq("red") | eq("green") | eq("yellow")
      #
      # @note The negative form (`expect(...).not_to matcher.or other`)
      #   is not supported at this time.
      def or(matcher)
        BuiltIn::Compound::Or.new self, matcher
      end
      alias | or

      # Delegates to `#matches?`. Allows matchers to be used in composable
      # fashion and also supports using matchers in case statements.
      def ===(value)
        matches?(value)
      end

    private

      # This provides a generic way to fuzzy-match an expected value against
      # an actual value. It understands nested data structures (e.g. hashes
      # and arrays) and is able to match against a matcher being used as
      # the expected value or within the expected value at any level of
      # nesting.
      #
      # Within a custom matcher you are encouraged to use this whenever your
      # matcher needs to match two values, unless it needs more precise semantics.
      # For example, the `eq` matcher _does not_ use this as it is meant to
      # use `==` (and only `==`) for matching.
      #
      # @param expected [Object] what is expected
      # @param actual [Object] the actual value
      #
      # @!visibility public
      def values_match?(expected, actual)
        expected = with_matchers_cloned(expected)
        Support::FuzzyMatcher.values_match?(expected, actual)
      end

      # Returns the description of the given object in a way that is
      # aware of composed matchers. If the object is a matcher with
      # a `description` method, returns the description; otherwise
      # returns `object.inspect`.
      #
      # You are encouraged to use this in your custom matcher's
      # `description`, `failure_message` or
      # `failure_message_when_negated` implementation if you are
      # supporting matcher arguments.
      #
      # @!visibility public
      def description_of(object)
        RSpec::Support::ObjectFormatter.format(object)
      end

      # Transforms the given data structue (typically a hash or array)
      # into a new data structure that, when `#inspect` is called on it,
      # will provide descriptions of any contained matchers rather than
      # the normal `#inspect` output.
      #
      # You are encouraged to use this in your custom matcher's
      # `description`, `failure_message` or
      # `failure_message_when_negated` implementation if you are
      # supporting any arguments which may be a data structure
      # containing matchers.
      #
      # @!visibility public
      def surface_descriptions_in(item)
        if Matchers.is_a_describable_matcher?(item)
          DescribableItem.new(item)
        elsif Hash === item
          Hash[surface_descriptions_in(item.to_a)]
        elsif Struct === item || unreadable_io?(item)
          RSpec::Support::ObjectFormatter.format(item)
        elsif should_enumerate?(item)
          item.map { |subitem| surface_descriptions_in(subitem) }
        else
          item
        end
      end

      # @private
      # Historically, a single matcher instance was only checked
      # against a single value. Given that the matcher was only
      # used once, it's been common to memoize some intermediate
      # calculation that is derived from the `actual` value in
      # order to reuse that intermediate result in the failure
      # message.
      #
      # This can cause a problem when using such a matcher as an
      # argument to another matcher in a composed matcher expression,
      # since the matcher instance may be checked against multiple
      # values and produce invalid results due to the memoization.
      #
      # To deal with this, we clone any matchers in `expected` via
      # this method when using `values_match?`, so that any memoization
      # does not "leak" between checks.
      def with_matchers_cloned(object)
        if Matchers.is_a_matcher?(object)
          object.clone
        elsif Hash === object
          Hash[with_matchers_cloned(object.to_a)]
        elsif should_enumerate?(object)
          object.map { |subobject| with_matchers_cloned(subobject) }
        else
          object
        end
      end

      # @api private
      # We should enumerate arrays as long as they are not recursive.
      def should_enumerate?(item)
        Array === item && item.none? { |subitem| subitem.equal?(item) }
      end

      # @api private
      def unreadable_io?(object)
        return false unless IO === object
        object.each {} # STDOUT is enumerable but raises an error
        false
      rescue IOError
        true
      end
      module_function :surface_descriptions_in, :should_enumerate?, :unreadable_io?

      # Wraps an item in order to surface its `description` via `inspect`.
      # @api private
      DescribableItem = Struct.new(:item) do
        # Inspectable version of the item description
        def inspect
          "(#{item.description})"
        end

        # A pretty printed version of the item description.
        def pretty_print(pp)
          pp.text "(#{item.description})"
        end
      end
    end
  end
end
