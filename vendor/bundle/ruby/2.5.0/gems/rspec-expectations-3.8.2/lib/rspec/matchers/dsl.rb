module RSpec
  module Matchers
    # Defines the custom matcher DSL.
    module DSL
      # Defines a matcher alias. The returned matcher's `description` will be overriden
      # to reflect the phrasing of the new name, which will be used in failure messages
      # when passed as an argument to another matcher in a composed matcher expression.
      #
      # @example
      #   RSpec::Matchers.alias_matcher :a_list_that_sums_to, :sum_to
      #   sum_to(3).description # => "sum to 3"
      #   a_list_that_sums_to(3).description # => "a list that sums to 3"
      #
      # @example
      #   RSpec::Matchers.alias_matcher :a_list_sorted_by, :be_sorted_by do |description|
      #     description.sub("be sorted by", "a list sorted by")
      #   end
      #
      #   be_sorted_by(:age).description # => "be sorted by age"
      #   a_list_sorted_by(:age).description # => "a list sorted by age"
      #
      # @param new_name [Symbol] the new name for the matcher
      # @param old_name [Symbol] the original name for the matcher
      # @param options  [Hash] options for the aliased matcher
      # @option options [Class] :klass the ruby class to use as the decorator. (Not normally used).
      # @yield [String] optional block that, when given, is used to define the overriden
      #   logic. The yielded arg is the original description or failure message. If no
      #   block is provided, a default override is used based on the old and new names.
      # @see RSpec::Matchers
      def alias_matcher(new_name, old_name, options={}, &description_override)
        description_override ||= lambda do |old_desc|
          old_desc.gsub(EnglishPhrasing.split_words(old_name), EnglishPhrasing.split_words(new_name))
        end
        klass = options.fetch(:klass) { AliasedMatcher }

        define_method(new_name) do |*args, &block|
          matcher = __send__(old_name, *args, &block)
          matcher.matcher_name = new_name if matcher.respond_to?(:matcher_name=)
          klass.new(matcher, description_override)
        end
      end

      # Defines a negated matcher. The returned matcher's `description` and `failure_message`
      # will be overriden to reflect the phrasing of the new name, and the match logic will
      # be based on the original matcher but negated.
      #
      # @example
      #   RSpec::Matchers.define_negated_matcher :exclude, :include
      #   include(1, 2).description # => "include 1 and 2"
      #   exclude(1, 2).description # => "exclude 1 and 2"
      #
      # @param negated_name [Symbol] the name for the negated matcher
      # @param base_name [Symbol] the name of the original matcher that will be negated
      # @yield [String] optional block that, when given, is used to define the overriden
      #   logic. The yielded arg is the original description or failure message. If no
      #   block is provided, a default override is used based on the old and new names.
      # @see RSpec::Matchers
      def define_negated_matcher(negated_name, base_name, &description_override)
        alias_matcher(negated_name, base_name, :klass => AliasedNegatedMatcher, &description_override)
      end

      # Defines a custom matcher.
      #
      # @param name [Symbol] the name for the matcher
      # @yield [Object] block that is used to define the matcher.
      #   The block is evaluated in the context of your custom matcher class.
      #   When args are passed to your matcher, they will be yielded here,
      #   usually representing the expected value(s).
      # @see RSpec::Matchers
      def define(name, &declarations)
        warn_about_block_args(name, declarations)
        define_method name do |*expected, &block_arg|
          RSpec::Matchers::DSL::Matcher.new(name, declarations, self, *expected, &block_arg)
        end
      end
      alias_method :matcher, :define

    private

      if Proc.method_defined?(:parameters)
        def warn_about_block_args(name, declarations)
          declarations.parameters.each do |type, arg_name|
            next unless type == :block
            RSpec.warning("Your `#{name}` custom matcher receives a block argument (`#{arg_name}`), " \
                          "but due to limitations in ruby, RSpec cannot provide the block. Instead, " \
                          "use the `block_arg` method to access the block")
          end
        end
      else
        # :nocov:
        def warn_about_block_args(*)
          # There's no way to detect block params on 1.8 since the method reflection APIs don't expose it
        end
        # :nocov:
      end

      RSpec.configure { |c| c.extend self } if RSpec.respond_to?(:configure)

      # Contains the methods that are available from within the
      # `RSpec::Matchers.define` DSL for creating custom matchers.
      module Macros
        # Stores the block that is used to determine whether this matcher passes
        # or fails. The block should return a boolean value. When the matcher is
        # passed to `expect(...).to` and the block returns `true`, then the expectation
        # passes. Similarly, when the matcher is passed to `expect(...).not_to` and the
        # block returns `false`, then the expectation passes.
        #
        # @example
        #
        #     RSpec::Matchers.define :be_even do
        #       match do |actual|
        #         actual.even?
        #       end
        #     end
        #
        #     expect(4).to be_even     # passes
        #     expect(3).not_to be_even # passes
        #     expect(3).to be_even     # fails
        #     expect(4).not_to be_even # fails
        #
        # By default the match block will swallow expectation errors (e.g.
        # caused by using an expectation such as `expect(1).to eq 2`), if you
        # with to allow these to bubble up, pass in the option
        # `:notify_expectation_failures => true`.
        #
        # @param [Hash] options for defining the behavior of the match block.
        # @yield [Object] actual the actual value (i.e. the value wrapped by `expect`)
        def match(options={}, &match_block)
          define_user_override(:matches?, match_block) do |actual|
            @actual = actual
            RSpec::Support.with_failure_notifier(RAISE_NOTIFIER) do
              begin
                super(*actual_arg_for(match_block))
              rescue RSpec::Expectations::ExpectationNotMetError
                raise if options[:notify_expectation_failures]
                false
              end
            end
          end
        end

        # @private
        RAISE_NOTIFIER = Proc.new { |err, _opts| raise err }

        # Use this to define the block for a negative expectation (`expect(...).not_to`)
        # when the positive and negative forms require different handling. This
        # is rarely necessary, but can be helpful, for example, when specifying
        # asynchronous processes that require different timeouts.
        #
        # @yield [Object] actual the actual value (i.e. the value wrapped by `expect`)
        def match_when_negated(&match_block)
          define_user_override(:does_not_match?, match_block) do |actual|
            begin
              @actual = actual
              RSpec::Support.with_failure_notifier(RAISE_NOTIFIER) do
                super(*actual_arg_for(match_block))
              end
            rescue RSpec::Expectations::ExpectationNotMetError
              false
            end
          end
        end

        # Use this instead of `match` when the block will raise an exception
        # rather than returning false to indicate a failure.
        #
        # @example
        #
        #     RSpec::Matchers.define :accept_as_valid do |candidate_address|
        #       match_unless_raises ValidationException do |validator|
        #         validator.validate(candidate_address)
        #       end
        #     end
        #
        #     expect(email_validator).to accept_as_valid("person@company.com")
        #
        # @yield [Object] actual the actual object (i.e. the value wrapped by `expect`)
        def match_unless_raises(expected_exception=Exception, &match_block)
          define_user_override(:matches?, match_block) do |actual|
            @actual = actual
            begin
              super(*actual_arg_for(match_block))
            rescue expected_exception => @rescued_exception
              false
            else
              true
            end
          end
        end

        # Customizes the failure messsage to use when this matcher is
        # asked to positively match. Only use this when the message
        # generated by default doesn't suit your needs.
        #
        # @example
        #
        #     RSpec::Matchers.define :have_strength do |expected|
        #       match { your_match_logic }
        #
        #       failure_message do |actual|
        #         "Expected strength of #{expected}, but had #{actual.strength}"
        #       end
        #     end
        #
        # @yield [Object] actual the actual object (i.e. the value wrapped by `expect`)
        def failure_message(&definition)
          define_user_override(__method__, definition)
        end

        # Customize the failure messsage to use when this matcher is asked
        # to negatively match. Only use this when the message generated by
        # default doesn't suit your needs.
        #
        # @example
        #
        #     RSpec::Matchers.define :have_strength do |expected|
        #       match { your_match_logic }
        #
        #       failure_message_when_negated do |actual|
        #         "Expected not to have strength of #{expected}, but did"
        #       end
        #     end
        #
        # @yield [Object] actual the actual object (i.e. the value wrapped by `expect`)
        def failure_message_when_negated(&definition)
          define_user_override(__method__, definition)
        end

        # Customize the description to use for one-liners.  Only use this when
        # the description generated by default doesn't suit your needs.
        #
        # @example
        #
        #     RSpec::Matchers.define :qualify_for do |expected|
        #       match { your_match_logic }
        #
        #       description do
        #         "qualify for #{expected}"
        #       end
        #     end
        #
        # @yield [Object] actual the actual object (i.e. the value wrapped by `expect`)
        def description(&definition)
          define_user_override(__method__, definition)
        end

        # Tells the matcher to diff the actual and expected values in the failure
        # message.
        def diffable
          define_method(:diffable?) { true }
        end

        # Declares that the matcher can be used in a block expectation.
        # Users will not be able to use your matcher in a block
        # expectation without declaring this.
        # (e.g. `expect { do_something }.to matcher`).
        def supports_block_expectations
          define_method(:supports_block_expectations?) { true }
        end

        # Convenience for defining methods on this matcher to create a fluent
        # interface. The trick about fluent interfaces is that each method must
        # return self in order to chain methods together. `chain` handles that
        # for you. If the method is invoked and the
        # `include_chain_clauses_in_custom_matcher_descriptions` config option
        # hash been enabled, the chained method name and args will be added to the
        # default description and failure message.
        #
        # In the common case where you just want the chained method to store some
        # value(s) for later use (e.g. in `match`), you can provide one or more
        # attribute names instead of a block; the chained method will store its
        # arguments in instance variables with those names, and the values will
        # be exposed via getters.
        #
        # @example
        #
        #     RSpec::Matchers.define :have_errors_on do |key|
        #       chain :with do |message|
        #         @message = message
        #       end
        #
        #       match do |actual|
        #         actual.errors[key] == @message
        #       end
        #     end
        #
        #     expect(minor).to have_errors_on(:age).with("Not old enough to participate")
        def chain(method_name, *attr_names, &definition)
          unless block_given? ^ attr_names.any?
            raise ArgumentError, "You must pass either a block or some attribute names (but not both) to `chain`."
          end

          definition = assign_attributes(attr_names) if attr_names.any?

          define_user_override(method_name, definition) do |*args, &block|
            super(*args, &block)
            @chained_method_clauses.push([method_name, args])
            self
          end
        end

        def assign_attributes(attr_names)
          attr_reader(*attr_names)
          private(*attr_names)

          lambda do |*attr_values|
            attr_names.zip(attr_values) do |attr_name, attr_value|
              instance_variable_set(:"@#{attr_name}", attr_value)
            end
          end
        end

        # assign_attributes isn't defined in the private section below because
        # that makes MRI 1.9.2 emit a warning about private attributes.
        private :assign_attributes

      private

        # Does the following:
        #
        # - Defines the named method using a user-provided block
        #   in @user_method_defs, which is included as an ancestor
        #   in the singleton class in which we eval the `define` block.
        # - Defines an overriden definition for the same method
        #   usign the provided `our_def` block.
        # - Provides a default `our_def` block for the common case
        #   of needing to call the user's definition with `@actual`
        #   as an arg, but only if their block's arity can handle it.
        #
        # This compiles the user block into an actual method, allowing
        # them to use normal method constructs like `return`
        # (e.g. for an early guard statement), while allowing us to define
        # an override that can provide the wrapped handling
        # (e.g. assigning `@actual`, rescueing errors, etc) and
        # can `super` to the user's definition.
        def define_user_override(method_name, user_def, &our_def)
          @user_method_defs.__send__(:define_method, method_name, &user_def)
          our_def ||= lambda { super(*actual_arg_for(user_def)) }
          define_method(method_name, &our_def)
        end

        # Defines deprecated macro methods from RSpec 2 for backwards compatibility.
        # @deprecated Use the methods from {Macros} instead.
        module Deprecated
          # @deprecated Use {Macros#match} instead.
          def match_for_should(&definition)
            RSpec.deprecate("`match_for_should`", :replacement => "`match`")
            match(&definition)
          end

          # @deprecated Use {Macros#match_when_negated} instead.
          def match_for_should_not(&definition)
            RSpec.deprecate("`match_for_should_not`", :replacement => "`match_when_negated`")
            match_when_negated(&definition)
          end

          # @deprecated Use {Macros#failure_message} instead.
          def failure_message_for_should(&definition)
            RSpec.deprecate("`failure_message_for_should`", :replacement => "`failure_message`")
            failure_message(&definition)
          end

          # @deprecated Use {Macros#failure_message_when_negated} instead.
          def failure_message_for_should_not(&definition)
            RSpec.deprecate("`failure_message_for_should_not`", :replacement => "`failure_message_when_negated`")
            failure_message_when_negated(&definition)
          end
        end
      end

      # Defines default implementations of the matcher
      # protocol methods for custom matchers. You can
      # override any of these using the {RSpec::Matchers::DSL::Macros Macros} methods
      # from within an `RSpec::Matchers.define` block.
      module DefaultImplementations
        include BuiltIn::BaseMatcher::DefaultFailureMessages

        # @api private
        # Used internally by objects returns by `should` and `should_not`.
        def diffable?
          false
        end

        # The default description.
        def description
          english_name = EnglishPhrasing.split_words(name)
          expected_list = EnglishPhrasing.list(expected)
          "#{english_name}#{expected_list}#{chained_method_clause_sentences}"
        end

        # Matchers do not support block expectations by default. You
        # must opt-in.
        def supports_block_expectations?
          false
        end

        # Most matchers do not expect call stack jumps.
        def expects_call_stack_jump?
          false
        end

      private

        def chained_method_clause_sentences
          return '' unless Expectations.configuration.include_chain_clauses_in_custom_matcher_descriptions?

          @chained_method_clauses.map do |(method_name, method_args)|
            english_name = EnglishPhrasing.split_words(method_name)
            arg_list = EnglishPhrasing.list(method_args)
            " #{english_name}#{arg_list}"
          end.join
        end
      end

      # The class used for custom matchers. The block passed to
      # `RSpec::Matchers.define` will be evaluated in the context
      # of the singleton class of an instance, and will have the
      # {RSpec::Matchers::DSL::Macros Macros} methods available.
      class Matcher
        # Provides default implementations for the matcher protocol methods.
        include DefaultImplementations

        # Allows expectation expressions to be used in the match block.
        include RSpec::Matchers

        # Supports the matcher composability features of RSpec 3+.
        include Composable

        # Makes the macro methods available to an `RSpec::Matchers.define` block.
        extend Macros
        extend Macros::Deprecated

        # Exposes the value being matched against -- generally the object
        # object wrapped by `expect`.
        attr_reader :actual

        # Exposes the exception raised during the matching by `match_unless_raises`.
        # Could be useful to extract details for a failure message.
        attr_reader :rescued_exception

        # The block parameter used in the expectation
        attr_reader :block_arg

        # The name of the matcher.
        attr_reader :name

        # @api private
        def initialize(name, declarations, matcher_execution_context, *expected, &block_arg)
          @name     = name
          @actual   = nil
          @expected_as_array = expected
          @matcher_execution_context = matcher_execution_context
          @chained_method_clauses = []
          @block_arg = block_arg

          class << self
            # See `Macros#define_user_override` above, for an explanation.
            include(@user_method_defs = Module.new)
            self
          end.class_exec(*expected, &declarations)
        end

        # Provides the expected value. This will return an array if
        # multiple arguments were passed to the matcher; otherwise it
        # will return a single value.
        # @see #expected_as_array
        def expected
          if expected_as_array.size == 1
            expected_as_array[0]
          else
            expected_as_array
          end
        end

        # Returns the expected value as an an array. This exists primarily
        # to aid in upgrading from RSpec 2.x, since in RSpec 2, `expected`
        # always returned an array.
        # @see #expected
        attr_reader :expected_as_array

        # Adds the name (rather than a cryptic hex number)
        # so we can identify an instance of
        # the matcher in error messages (e.g. for `NoMethodError`)
        def inspect
          "#<#{self.class.name} #{name}>"
        end

        if RUBY_VERSION.to_f >= 1.9
          # Indicates that this matcher responds to messages
          # from the `@matcher_execution_context` as well.
          # Also, supports getting a method object for such methods.
          def respond_to_missing?(method, include_private=false)
            super || @matcher_execution_context.respond_to?(method, include_private)
          end
        else # for 1.8.7
          # :nocov:
          # Indicates that this matcher responds to messages
          # from the `@matcher_execution_context` as well.
          def respond_to?(method, include_private=false)
            super || @matcher_execution_context.respond_to?(method, include_private)
          end
          # :nocov:
        end

      private

        def actual_arg_for(block)
          block.arity.zero? ? [] : [@actual]
        end

        # Takes care of forwarding unhandled messages to the
        # `@matcher_execution_context` (typically the current
        # running `RSpec::Core::Example`). This is needed by
        # rspec-rails so that it can define matchers that wrap
        # Rails' test helper methods, but it's also a useful
        # feature in its own right.
        def method_missing(method, *args, &block)
          if @matcher_execution_context.respond_to?(method)
            @matcher_execution_context.__send__ method, *args, &block
          else
            super(method, *args, &block)
          end
        end
      end
    end
  end
end
