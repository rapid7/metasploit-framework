module RSpec
  module Matchers
    module BuiltIn
      # @api private
      # Provides the implementation for `has_<predicate>`.
      # Not intended to be instantiated directly.
      class Has < BaseMatcher
        def initialize(method_name, *args, &block)
          @method_name, @args, @block = method_name, args, block
        end

        # @private
        def matches?(actual, &block)
          @actual = actual
          @block ||= block
          predicate_accessible? && predicate_matches?
        end

        # @private
        def does_not_match?(actual, &block)
          @actual = actual
          @block ||= block
          predicate_accessible? && !predicate_matches?
        end

        # @api private
        # @return [String]
        def failure_message
          validity_message || "expected ##{predicate}#{failure_message_args_description} to return true, got false"
        end

        # @api private
        # @return [String]
        def failure_message_when_negated
          validity_message || "expected ##{predicate}#{failure_message_args_description} to return false, got true"
        end

        # @api private
        # @return [String]
        def description
          [method_description, args_description].compact.join(' ')
        end

      private

        def predicate_accessible?
          !private_predicate? && predicate_exists?
        end

        # support 1.8.7, evaluate once at load time for performance
        if String === methods.first
          # :nocov:
          def private_predicate?
            @actual.private_methods.include? predicate.to_s
          end
          # :nocov:
        else
          def private_predicate?
            @actual.private_methods.include? predicate
          end
        end

        def predicate_exists?
          @actual.respond_to? predicate
        end

        def predicate_matches?
          @actual.__send__(predicate, *@args, &@block)
        end

        def predicate
          # On 1.9, there appears to be a bug where String#match can return `false`
          # rather than the match data object. Changing to Regex#match appears to
          # work around this bug. For an example of this bug, see:
          # https://travis-ci.org/rspec/rspec-expectations/jobs/27549635
          @predicate ||= :"has_#{Matchers::HAS_REGEX.match(@method_name.to_s).captures.first}?"
        end

        def method_description
          @method_name.to_s.tr('_', ' ')
        end

        def args_description
          return nil if @args.empty?
          @args.map { |arg| RSpec::Support::ObjectFormatter.format(arg) }.join(', ')
        end

        def failure_message_args_description
          desc = args_description
          "(#{desc})" if desc
        end

        def validity_message
          if private_predicate?
            "expected #{@actual} to respond to `#{predicate}` but `#{predicate}` is a private method"
          elsif !predicate_exists?
            "expected #{@actual} to respond to `#{predicate}`"
          end
        end
      end
    end
  end
end
