module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `exist`.
      # Not intended to be instantiated directly.
      class Exist < BaseMatcher
        def initialize(*expected)
          @expected = expected
        end

        # @api private
        # @return [Boolean]
        def matches?(actual)
          @actual = actual
          @test = ExistenceTest.new @actual, @expected
          @test.valid_test? && @test.actual_exists?
        end

        # @api private
        # @return [Boolean]
        def does_not_match?(actual)
          @actual = actual
          @test = ExistenceTest.new @actual, @expected
          @test.valid_test? && !@test.actual_exists?
        end

        # @api private
        # @return [String]
        def failure_message
          "expected #{actual_formatted} to exist#{@test.validity_message}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected #{actual_formatted} not to exist#{@test.validity_message}"
        end

        # @api private
        # Simple class for memoizing actual/expected for this matcher
        # and examining the match
        class ExistenceTest < Struct.new(:actual, :expected)
          # @api private
          # @return [Boolean]
          def valid_test?
            uniq_truthy_values.size == 1
          end

          # @api private
          # @return [Boolean]
          def actual_exists?
            existence_values.first
          end

          # @api private
          # @return [String]
          def validity_message
            case uniq_truthy_values.size
            when 0
              " but it does not respond to either `exist?` or `exists?`"
            when 2
              " but `exist?` and `exists?` returned different values:\n\n"\
              " exist?: #{existence_values.first}\n"\
              "exists?: #{existence_values.last}"
            end
          end

        private

          def uniq_truthy_values
            @uniq_truthy_values ||= existence_values.map { |v| !!v }.uniq
          end

          def existence_values
            @existence_values ||= predicates.map { |p| actual.__send__(p, *expected) }
          end

          def predicates
            @predicates ||= [:exist?, :exists?].select { |p| actual.respond_to?(p) && !deprecated(p, actual) }
          end

          def deprecated(predicate, actual)
            predicate == :exists? && File == actual
          end
        end
      end
    end
  end
end
