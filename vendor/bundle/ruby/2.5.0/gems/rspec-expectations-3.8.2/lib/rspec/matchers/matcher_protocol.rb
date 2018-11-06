module RSpec
  module Matchers
    # rspec-expectations can work with any matcher object that implements this protocol.
    #
    # @note This class is not loaded at runtime by rspec-expectations. It exists
    #   purely to provide documentation for the matcher protocol.
    class MatcherProtocol
      # @!group Required Methods

      # @!method matches?(actual)
      #   @param actual [Object] The object being matched against.
      #   @yield For an expression like `expect(x).to matcher do...end`, the `do/end`
      #     block binds to `to`. It passes that block, if there is one, on to this method.
      #   @return [Boolean] true if this matcher matches the provided object.

      # @!method failure_message
      #   This will only be called if {#matches?} returns false.
      #   @return [String] Explanation for the failure.

      # @!endgroup

      # @!group Optional Methods

      # @!method does_not_match?(actual)
      #   In a negative expectation such as `expect(x).not_to foo`, RSpec will
      #   call `foo.does_not_match?(x)` if this method is defined. If it's not
      #   defined it will fall back to using `!foo.matches?(x)`. This allows you
      #   to provide custom logic for the negative case.
      #
      #   @param actual [Object] The object being matched against.
      #   @yield For an expression like `expect(x).not_to matcher do...end`, the `do/end`
      #     block binds to `not_to`. It passes that block, if there is one, on to this method.
      #   @return [Boolean] true if this matcher does not match the provided object.

      # @!method failure_message_when_negated
      #   This will only be called when a negative match fails.
      #   @return [String] Explanation for the failure.
      #   @note This method is listed as optional because matchers do not have to
      #     support negation. But if your matcher does support negation, this is a
      #     required method -- otherwise, you'll get a `NoMethodError`.

      # @!method description
      #   The description is used for two things:
      #
      #     * When using RSpec's one-liner syntax
      #       (e.g. `it { is_expected.to matcher }`), the description
      #       is used to generate the example's doc string since you
      #       have not provided one.
      #     * In a composed matcher expression, the description is used
      #       as part of the failure message (and description) of the outer
      #       matcher.
      #
      #   @return [String] Description of the matcher.

      # @!method supports_block_expectations?
      #   Indicates that this matcher can be used in a block expectation expression,
      #   such as `expect { foo }.to raise_error`. Generally speaking, this is
      #   only needed for matchers which operate on a side effect of a block, rather
      #   than on a particular object.
      #   @return [Boolean] true if this matcher can be used in block expressions.
      #   @note If not defined, RSpec assumes a value of `false` for this method.

      # @!method expects_call_stack_jump?
      #   Indicates that when this matcher is used in a block expectation
      #   expression, it expects the block to use a ruby construct that causes
      #   a call stack jump (such as raising an error or throwing a symbol).
      #
      #   This is used internally for compound block expressions, as matchers
      #   which expect call stack jumps must be treated with care to work properly.
      #
      #   @return [Boolean] true if the matcher expects a call stack jump
      #
      #   @note This method is very rarely used or needed.
      #   @note If not defined, RSpec assumes a value of `false` for this method.

      # @!method diffable?
      #   @return [Boolean] true if `actual` and `expected` can be diffed.
      #   Indicates that this matcher provides `actual` and `expected` attributes,
      #   and that the values returned by these can be usefully diffed, which can
      #   be included in the output.

      # @!method actual
      #   @return [String, Object] If an object (rather than a string) is provided,
      #     RSpec will use the `pp` library to convert it to multi-line output in
      #     order to diff.
      #   The actual value for the purposes of a diff.
      #   @note This method is required if `diffable?` returns true.

      # @!method expected
      #   @return [String, Object] If an object (rather than a string) is provided,
      #     RSpec will use the `pp` library to convert it to multi-line output in
      #     order to diff.
      #   The expected value for the purposes of a diff.
      #   @note This method is required if `diffable?` returns true.

      # @!endgroup
    end
  end
end
