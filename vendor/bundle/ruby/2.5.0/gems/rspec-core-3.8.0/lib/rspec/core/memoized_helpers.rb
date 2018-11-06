RSpec::Support.require_rspec_support 'reentrant_mutex'

module RSpec
  module Core
    # This module is included in {ExampleGroup}, making the methods
    # available to be called from within example blocks.
    #
    # @see ClassMethods
    module MemoizedHelpers
      # @note `subject` was contributed by Joe Ferris to support the one-liner
      #   syntax embraced by shoulda matchers:
      #
      #       describe Widget do
      #         it { is_expected.to validate_presence_of(:name) }
      #         # or
      #         it { should validate_presence_of(:name) }
      #       end
      #
      #   While the examples below demonstrate how to use `subject`
      #   explicitly in examples, we recommend that you define a method with
      #   an intention revealing name instead.
      #
      # @example
      #
      #   # Explicit declaration of subject.
      #   describe Person do
      #     subject { Person.new(:birthdate => 19.years.ago) }
      #     it "should be eligible to vote" do
      #       subject.should be_eligible_to_vote
      #       # ^ ^ explicit reference to subject not recommended
      #     end
      #   end
      #
      #   # Implicit subject => { Person.new }.
      #   describe Person do
      #     it "should be eligible to vote" do
      #       subject.should be_eligible_to_vote
      #       # ^ ^ explicit reference to subject not recommended
      #     end
      #   end
      #
      #   # One-liner syntax - expectation is set on the subject.
      #   describe Person do
      #     it { is_expected.to be_eligible_to_vote }
      #     # or
      #     it { should be_eligible_to_vote }
      #   end
      #
      # @note Because `subject` is designed to create state that is reset
      #   between each example, and `before(:context)` is designed to setup
      #   state that is shared across _all_ examples in an example group,
      #   `subject` is _not_ intended to be used in a `before(:context)` hook.
      #
      # @see #should
      # @see #should_not
      # @see #is_expected
      def subject
        __memoized.fetch_or_store(:subject) do
          described = described_class || self.class.metadata.fetch(:description_args).first
          Class === described ? described.new : described
        end
      end

      # When `should` is called with no explicit receiver, the call is
      # delegated to the object returned by `subject`. Combined with an
      # implicit subject this supports very concise expressions.
      #
      # @example
      #
      #   describe Person do
      #     it { should be_eligible_to_vote }
      #   end
      #
      # @see #subject
      # @see #is_expected
      #
      # @note This only works if you are using rspec-expectations.
      # @note If you are using RSpec's newer expect-based syntax you may
      #       want to use `is_expected.to` instead of `should`.
      def should(matcher=nil, message=nil)
        RSpec::Expectations::PositiveExpectationHandler.handle_matcher(subject, matcher, message)
      end

      # Just like `should`, `should_not` delegates to the subject (implicit or
      # explicit) of the example group.
      #
      # @example
      #
      #   describe Person do
      #     it { should_not be_eligible_to_vote }
      #   end
      #
      # @see #subject
      # @see #is_expected
      #
      # @note This only works if you are using rspec-expectations.
      # @note If you are using RSpec's newer expect-based syntax you may
      #       want to use `is_expected.to_not` instead of `should_not`.
      def should_not(matcher=nil, message=nil)
        RSpec::Expectations::NegativeExpectationHandler.handle_matcher(subject, matcher, message)
      end

      # Wraps the `subject` in `expect` to make it the target of an expectation.
      # Designed to read nicely for one-liners.
      #
      # @example
      #
      #   describe [1, 2, 3] do
      #     it { is_expected.to be_an Array }
      #     it { is_expected.not_to include 4 }
      #   end
      #
      # @see #subject
      # @see #should
      # @see #should_not
      #
      # @note This only works if you are using rspec-expectations.
      def is_expected
        expect(subject)
      end

      # @private
      # should just be placed in private section,
      # but Ruby issues warnings on private attributes.
      # and expanding it to the equivalent method upsets Rubocop,
      # b/c it should obviously be a reader
      attr_reader :__memoized
      private :__memoized

    private

      # @private
      def initialize(*)
        __init_memoized
        super
      end

      # @private
      def __init_memoized
        @__memoized = if RSpec.configuration.threadsafe?
                        ThreadsafeMemoized.new
                      else
                        NonThreadSafeMemoized.new
                      end
      end

      # @private
      class ThreadsafeMemoized
        def initialize
          @memoized = {}
          @mutex = Support::ReentrantMutex.new
        end

        def fetch_or_store(key)
          @memoized.fetch(key) do # only first access pays for synchronization
            @mutex.synchronize do
              @memoized.fetch(key) { @memoized[key] = yield }
            end
          end
        end
      end

      # @private
      class NonThreadSafeMemoized
        def initialize
          @memoized = {}
        end

        def fetch_or_store(key)
          @memoized.fetch(key) { @memoized[key] = yield }
        end
      end

      # Used internally to customize the behavior of the
      # memoized hash when used in a `before(:context)` hook.
      #
      # @private
      class ContextHookMemoized
        def self.isolate_for_context_hook(example_group_instance)
          exploding_memoized = self

          example_group_instance.instance_exec do
            @__memoized = exploding_memoized

            begin
              yield
            ensure
              # This is doing a reset instead of just isolating for context hook.
              # Really, this should set the old @__memoized back into place.
              #
              # Caller is the before and after context hooks
              # which are both called from self.run
              # I didn't look at why it made tests fail, maybe an object was getting reused in RSpec tests,
              # if so, then that probably already works, and its the tests that are wrong.
              __init_memoized
            end
          end
        end

        def self.fetch_or_store(key, &_block)
          description = if key == :subject
                          "subject"
                        else
                          "let declaration `#{key}`"
                        end

          raise <<-EOS
#{description} accessed in #{article} #{hook_expression} hook at:
  #{CallerFilter.first_non_rspec_line}

`let` and `subject` declarations are not intended to be called
in #{article} #{hook_expression} hook, as they exist to define state that
is reset between each example, while #{hook_expression} exists to
#{hook_intention}.
EOS
        end

        # @private
        class Before < self
          def self.hook_expression
            "`before(:context)`"
          end

          def self.article
            "a"
          end

          def self.hook_intention
            "define state that is shared across examples in an example group"
          end
        end

        # @private
        class After < self
          def self.hook_expression
            "`after(:context)`"
          end

          def self.article
            "an"
          end

          def self.hook_intention
            "cleanup state that is shared across examples in an example group"
          end
        end
      end

      # This module is extended onto {ExampleGroup}, making the methods
      # available to be called from within example group blocks.
      # You can think of them as being analagous to class macros.
      module ClassMethods
        # Generates a method whose return value is memoized after the first
        # call. Useful for reducing duplication between examples that assign
        # values to the same local variable.
        #
        # @note `let` _can_ enhance readability when used sparingly (1,2, or
        #   maybe 3 declarations) in any given example group, but that can
        #   quickly degrade with overuse. YMMV.
        #
        # @note `let` can be configured to be threadsafe or not.
        #   If it is threadsafe, it will take longer to access the value.
        #   If it is not threadsafe, it may behave in surprising ways in examples
        #   that spawn separate threads. Specify this on `RSpec.configure`
        #
        # @note Because `let` is designed to create state that is reset between
        #   each example, and `before(:context)` is designed to setup state that
        #   is shared across _all_ examples in an example group, `let` is _not_
        #   intended to be used in a `before(:context)` hook.
        #
        # @example
        #
        #   describe Thing do
        #     let(:thing) { Thing.new }
        #
        #     it "does something" do
        #       # First invocation, executes block, memoizes and returns result.
        #       thing.do_something
        #
        #       # Second invocation, returns the memoized value.
        #       thing.should be_something
        #     end
        #   end
        def let(name, &block)
          # We have to pass the block directly to `define_method` to
          # allow it to use method constructs like `super` and `return`.
          raise "#let or #subject called without a block" if block.nil?
          raise(
            "#let or #subject called with a reserved name #initialize"
          ) if :initialize == name
          MemoizedHelpers.module_for(self).__send__(:define_method, name, &block)

          # Apply the memoization. The method has been defined in an ancestor
          # module so we can use `super` here to get the value.
          if block.arity == 1
            define_method(name) { __memoized.fetch_or_store(name) { super(RSpec.current_example, &nil) } }
          else
            define_method(name) { __memoized.fetch_or_store(name) { super(&nil) } }
          end
        end

        # Just like `let`, except the block is invoked by an implicit `before`
        # hook. This serves a dual purpose of setting up state and providing a
        # memoized reference to that state.
        #
        # @example
        #
        #   class Thing
        #     def self.count
        #       @count ||= 0
        #     end
        #
        #     def self.count=(val)
        #       @count += val
        #     end
        #
        #     def self.reset_count
        #       @count = 0
        #     end
        #
        #     def initialize
        #       self.class.count += 1
        #     end
        #   end
        #
        #   describe Thing do
        #     after(:example) { Thing.reset_count }
        #
        #     context "using let" do
        #       let(:thing) { Thing.new }
        #
        #       it "is not invoked implicitly" do
        #         Thing.count.should eq(0)
        #       end
        #
        #       it "can be invoked explicitly" do
        #         thing
        #         Thing.count.should eq(1)
        #       end
        #     end
        #
        #     context "using let!" do
        #       let!(:thing) { Thing.new }
        #
        #       it "is invoked implicitly" do
        #         Thing.count.should eq(1)
        #       end
        #
        #       it "returns memoized version on first invocation" do
        #         thing
        #         Thing.count.should eq(1)
        #       end
        #     end
        #   end
        def let!(name, &block)
          let(name, &block)
          before { __send__(name) }
        end

        # Declares a `subject` for an example group which can then be wrapped
        # with `expect` using `is_expected` to make it the target of an
        # expectation in a concise, one-line example.
        #
        # Given a `name`, defines a method with that name which returns the
        # `subject`. This lets you declare the subject once and access it
        # implicitly in one-liners and explicitly using an intention revealing
        # name.
        #
        # When given a `name`, calling `super` in the block is not supported.
        #
        # @note `subject` can be configured to be threadsafe or not.
        #   If it is threadsafe, it will take longer to access the value.
        #   If it is not threadsafe, it may behave in surprising ways in examples
        #   that spawn separate threads. Specify this on `RSpec.configure`
        #
        # @param name [String,Symbol] used to define an accessor with an
        #   intention revealing name
        # @param block defines the value to be returned by `subject` in examples
        #
        # @example
        #
        #   describe CheckingAccount, "with $50" do
        #     subject { CheckingAccount.new(Money.new(50, :USD)) }
        #     it { is_expected.to have_a_balance_of(Money.new(50, :USD)) }
        #     it { is_expected.not_to be_overdrawn }
        #   end
        #
        #   describe CheckingAccount, "with a non-zero starting balance" do
        #     subject(:account) { CheckingAccount.new(Money.new(50, :USD)) }
        #     it { is_expected.not_to be_overdrawn }
        #     it "has a balance equal to the starting balance" do
        #       account.balance.should eq(Money.new(50, :USD))
        #     end
        #   end
        #
        # @see MemoizedHelpers#should
        # @see MemoizedHelpers#should_not
        # @see MemoizedHelpers#is_expected
        def subject(name=nil, &block)
          if name
            let(name, &block)
            alias_method :subject, name

            self::NamedSubjectPreventSuper.__send__(:define_method, name) do
              raise NotImplementedError, "`super` in named subjects is not supported"
            end
          else
            let(:subject, &block)
          end
        end

        # Just like `subject`, except the block is invoked by an implicit
        # `before` hook. This serves a dual purpose of setting up state and
        # providing a memoized reference to that state.
        #
        # @example
        #
        #   class Thing
        #     def self.count
        #       @count ||= 0
        #     end
        #
        #     def self.count=(val)
        #       @count += val
        #     end
        #
        #     def self.reset_count
        #       @count = 0
        #     end
        #
        #     def initialize
        #       self.class.count += 1
        #     end
        #   end
        #
        #   describe Thing do
        #     after(:example) { Thing.reset_count }
        #
        #     context "using subject" do
        #       subject { Thing.new }
        #
        #       it "is not invoked implicitly" do
        #         Thing.count.should eq(0)
        #       end
        #
        #       it "can be invoked explicitly" do
        #         subject
        #         Thing.count.should eq(1)
        #       end
        #     end
        #
        #     context "using subject!" do
        #       subject!(:thing) { Thing.new }
        #
        #       it "is invoked implicitly" do
        #         Thing.count.should eq(1)
        #       end
        #
        #       it "returns memoized version on first invocation" do
        #         subject
        #         Thing.count.should eq(1)
        #       end
        #     end
        #   end
        def subject!(name=nil, &block)
          subject(name, &block)
          before { subject }
        end
      end

      # @private
      #
      # Gets the LetDefinitions module. The module is mixed into
      # the example group and is used to hold all let definitions.
      # This is done so that the block passed to `let` can be
      # forwarded directly on to `define_method`, so that all method
      # constructs (including `super` and `return`) can be used in
      # a `let` block.
      #
      # The memoization is provided by a method definition on the
      # example group that supers to the LetDefinitions definition
      # in order to get the value to memoize.
      def self.module_for(example_group)
        get_constant_or_yield(example_group, :LetDefinitions) do
          mod = Module.new do
            include(Module.new {
              example_group.const_set(:NamedSubjectPreventSuper, self)
            })
          end

          example_group.const_set(:LetDefinitions, mod)
          mod
        end
      end

      # @private
      def self.define_helpers_on(example_group)
        example_group.__send__(:include, module_for(example_group))
      end

      if Module.method(:const_defined?).arity == 1 # for 1.8
        # @private
        #
        # Gets the named constant or yields.
        # On 1.8, const_defined? / const_get do not take into
        # account the inheritance hierarchy.
        # :nocov:
        def self.get_constant_or_yield(example_group, name)
          if example_group.const_defined?(name)
            example_group.const_get(name)
          else
            yield
          end
        end
        # :nocov:
      else
        # @private
        #
        # Gets the named constant or yields.
        # On 1.9, const_defined? / const_get take into account the
        # the inheritance by default, and accept an argument to
        # disable this behavior. It's important that we don't
        # consider inheritance here; each example group level that
        # uses a `let` should get its own `LetDefinitions` module.
        def self.get_constant_or_yield(example_group, name)
          if example_group.const_defined?(name, (check_ancestors = false))
            example_group.const_get(name, check_ancestors)
          else
            yield
          end
        end
      end
    end
  end
end
