module RSpec
  module Matchers
    module BuiltIn
      # @api private
      #
      # Used _internally_ as a base class for matchers that ship with
      # rspec-expectations and rspec-rails.
      #
      # ### Warning:
      #
      # This class is for internal use, and subject to change without notice.
      # We strongly recommend that you do not base your custom matchers on this
      # class. If/when this changes, we will announce it and remove this warning.
      class BaseMatcher
        include RSpec::Matchers::Composable

        # @api private
        # Used to detect when no arg is passed to `initialize`.
        # `nil` cannot be used because it's a valid value to pass.
        UNDEFINED = Object.new.freeze

        # @private
        attr_reader :actual, :expected, :rescued_exception

        # @private
        attr_writer :matcher_name

        def initialize(expected=UNDEFINED)
          @expected = expected unless UNDEFINED.equal?(expected)
        end

        # @api private
        # Indicates if the match is successful. Delegates to `match`, which
        # should be defined on a subclass. Takes care of consistently
        # initializing the `actual` attribute.
        def matches?(actual)
          @actual = actual
          match(expected, actual)
        end

        # @api private
        # Used to wrap a block of code that will indicate failure by
        # raising one of the named exceptions.
        #
        # This is used by rspec-rails for some of its matchers that
        # wrap rails' assertions.
        def match_unless_raises(*exceptions)
          exceptions.unshift Exception if exceptions.empty?
          begin
            yield
            true
          rescue *exceptions => @rescued_exception
            false
          end
        end

        # @api private
        # Generates a description using {EnglishPhrasing}.
        # @return [String]
        def description
          desc = EnglishPhrasing.split_words(self.class.matcher_name)
          desc << EnglishPhrasing.list(@expected) if defined?(@expected)
          desc
        end

        # @api private
        # Matchers are not diffable by default. Override this to make your
        # subclass diffable.
        def diffable?
          false
        end

        # @api private
        # Most matchers are value matchers (i.e. meant to work with `expect(value)`)
        # rather than block matchers (i.e. meant to work with `expect { }`), so
        # this defaults to false. Block matchers must override this to return true.
        def supports_block_expectations?
          false
        end

        # @api private
        def expects_call_stack_jump?
          false
        end

        # @private
        def expected_formatted
          RSpec::Support::ObjectFormatter.format(@expected)
        end

        # @private
        def actual_formatted
          RSpec::Support::ObjectFormatter.format(@actual)
        end

        # @private
        def self.matcher_name
          @matcher_name ||= underscore(name.split('::').last)
        end

        # @private
        def matcher_name
          if defined?(@matcher_name)
            @matcher_name
          else
            self.class.matcher_name
          end
        end

        # @private
        # Borrowed from ActiveSupport.
        def self.underscore(camel_cased_word)
          word = camel_cased_word.to_s.dup
          word.gsub!(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
          word.gsub!(/([a-z\d])([A-Z])/, '\1_\2')
          word.tr!('-', '_')
          word.downcase!
          word
        end
        private_class_method :underscore

      private

        def assert_ivars(*expected_ivars)
          return unless (expected_ivars - present_ivars).any?
          ivar_list = EnglishPhrasing.list(expected_ivars)
          raise "#{self.class.name} needs to supply#{ivar_list}"
        end

        if RUBY_VERSION.to_f < 1.9
          # :nocov:
          def present_ivars
            instance_variables.map(&:to_sym)
          end
          # :nocov:
        else
          alias present_ivars instance_variables
        end

        # @private
        module HashFormatting
          # `{ :a => 5, :b => 2 }.inspect` produces:
          #
          #     {:a=>5, :b=>2}
          #
          # ...but it looks much better as:
          #
          #     {:a => 5, :b => 2}
          #
          # This is idempotent and safe to run on a string multiple times.
          def improve_hash_formatting(inspect_string)
            inspect_string.gsub(/(\S)=>(\S)/, '\1 => \2')
          end
          module_function :improve_hash_formatting
        end

        include HashFormatting

        # @api private
        # Provides default implementations of failure messages, based on the `description`.
        module DefaultFailureMessages
          # @api private
          # Provides a good generic failure message. Based on `description`.
          # When subclassing, if you are not satisfied with this failure message
          # you often only need to override `description`.
          # @return [String]
          def failure_message
            "expected #{description_of @actual} to #{description}".dup
          end

          # @api private
          # Provides a good generic negative failure message. Based on `description`.
          # When subclassing, if you are not satisfied with this failure message
          # you often only need to override `description`.
          # @return [String]
          def failure_message_when_negated
            "expected #{description_of @actual} not to #{description}".dup
          end

          # @private
          def self.has_default_failure_messages?(matcher)
            matcher.method(:failure_message).owner == self &&
              matcher.method(:failure_message_when_negated).owner == self
          rescue NameError
            false
          end
        end

        include DefaultFailureMessages
      end
    end
  end
end
