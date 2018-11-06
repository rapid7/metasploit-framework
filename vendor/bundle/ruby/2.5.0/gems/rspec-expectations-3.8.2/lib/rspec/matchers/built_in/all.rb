module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `all`.
      # Not intended to be instantiated directly.
      class All < BaseMatcher
        # @private
        attr_reader :matcher, :failed_objects

        def initialize(matcher)
          @matcher = matcher
          @failed_objects = {}
        end

        # @private
        def does_not_match?(_actual)
          raise NotImplementedError, '`expect().not_to all( matcher )` is not supported.'
        end

        # @api private
        # @return [String]
        def failure_message
          unless iterable?
            return "#{improve_hash_formatting(super)}, but was not iterable"
          end

          all_messages = [improve_hash_formatting(super)]
          failed_objects.each do |index, matcher_failure_message|
            all_messages << failure_message_for_item(index, matcher_failure_message)
          end
          all_messages.join("\n\n")
        end

        # @api private
        # @return [String]
        def description
          improve_hash_formatting "all #{description_of matcher}"
        end

      private

        def match(_expected, _actual)
          return false unless iterable?

          index_failed_objects
          failed_objects.empty?
        end

        def index_failed_objects
          actual.each_with_index do |actual_item, index|
            cloned_matcher = matcher.clone
            matches = cloned_matcher.matches?(actual_item)
            failed_objects[index] = cloned_matcher.failure_message unless matches
          end
        end

        def failure_message_for_item(index, failure_message)
          failure_message = indent_multiline_message(add_new_line_if_needed(failure_message))
          indent_multiline_message("object at index #{index} failed to match:#{failure_message}")
        end

        def add_new_line_if_needed(message)
          message.start_with?("\n") ? message : "\n#{message}"
        end

        def indent_multiline_message(message)
          message = message.sub(/\n+\z/, '')
          message.lines.map do |line|
            line =~ /\S/ ? '   ' + line : line
          end.join
        end

        def initialize_copy(other)
          @matcher = @matcher.clone
          super
        end

        def iterable?
          @actual.respond_to?(:each_with_index)
        end
      end
    end
  end
end
