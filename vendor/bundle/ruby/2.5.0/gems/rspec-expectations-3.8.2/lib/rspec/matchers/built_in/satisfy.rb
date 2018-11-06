module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `satisfy`.
      # Not intended to be instantiated directly.
      class Satisfy < BaseMatcher
        def initialize(description=nil, &block)
          @description = description
          @block = block
        end

        # @private
        def matches?(actual, &block)
          @block = block if block
          @actual = actual
          @block.call(actual)
        end

        # @private
        def description
          @description ||= "satisfy #{block_representation}"
        end

        # @api private
        # @return [String]
        def failure_message
          "expected #{actual_formatted} to #{description}"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          "expected #{actual_formatted} not to #{description}"
        end

      private

        if RSpec::Support::RubyFeatures.ripper_supported?
          def block_representation
            if (block_snippet = extract_block_snippet)
              "expression `#{block_snippet}`"
            else
              'block'
            end
          end

          def extract_block_snippet
            return nil unless @block
            Expectations::BlockSnippetExtractor.try_extracting_single_line_body_of(@block, matcher_name)
          end
        else
          def block_representation
            'block'
          end
        end
      end
    end
  end
end
