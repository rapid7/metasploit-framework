RSpec::Support.require_rspec_support 'recursive_const_methods'

module RSpec
  module Core
    # rubocop:disable Metrics/ClassLength

    # ExampleGroup and {Example} are the main structural elements of
    # rspec-core. Consider this example:
    #
    #     describe Thing do
    #       it "does something" do
    #       end
    #     end
    #
    # The object returned by `describe Thing` is a subclass of ExampleGroup.
    # The object returned by `it "does something"` is an instance of Example,
    # which serves as a wrapper for an instance of the ExampleGroup in which it
    # is declared.
    #
    # Example group bodies (e.g. `describe` or `context` blocks) are evaluated
    # in the context of a new subclass of ExampleGroup. Individual examples are
    # evaluated in the context of an instance of the specific ExampleGroup
    # subclass to which they belong.
    #
    # Besides the class methods defined here, there are other interesting macros
    # defined in {Hooks}, {MemoizedHelpers::ClassMethods} and
    # {SharedExampleGroup}. There are additional instance methods available to
    # your examples defined in {MemoizedHelpers} and {Pending}.
    class ExampleGroup
      extend Hooks

      include MemoizedHelpers
      extend MemoizedHelpers::ClassMethods
      include Pending
      extend SharedExampleGroup

      # Define a singleton method for the singleton class (remove the method if
      # it's already been defined).
      # @private
      def self.idempotently_define_singleton_method(name, &definition)
        (class << self; self; end).module_exec do
          remove_method(name) if method_defined?(name) && instance_method(name).owner == self
          define_method(name, &definition)
        end
      end

      # @!group Metadata

      # The [Metadata](Metadata) object associated with this group.
      # @see Metadata
      def self.metadata
        @metadata ||= nil
      end

      # Temporarily replace the provided metadata.
      # Intended primarily to allow an example group's singleton class
      # to return the metadata of the example that it exists for. This
      # is necessary for shared example group inclusion to work properly
      # with singleton example groups.
      # @private
      def self.with_replaced_metadata(meta)
        orig_metadata = metadata
        @metadata = meta
        yield
      ensure
        @metadata = orig_metadata
      end

      # @private
      # @return [Metadata] belonging to the parent of a nested {ExampleGroup}
      def self.superclass_metadata
        @superclass_metadata ||= superclass.respond_to?(:metadata) ? superclass.metadata : nil
      end

      # @private
      def self.delegate_to_metadata(*names)
        names.each do |name|
          idempotently_define_singleton_method(name) { metadata.fetch(name) }
        end
      end

      delegate_to_metadata :described_class, :file_path, :location

      # @return [String] the current example group description
      def self.description
        description = metadata[:description]
        RSpec.configuration.format_docstrings_block.call(description)
      end

      # Returns the class or module passed to the `describe` method (or alias).
      # Returns nil if the subject is not a class or module.
      # @example
      #     describe Thing do
      #       it "does something" do
      #         described_class == Thing
      #       end
      #     end
      #
      def described_class
        self.class.described_class
      end

      # @!endgroup

      # @!group Defining Examples

      # @private
      # @macro [attach] define_example_method
      #   @!scope class
      #   @method $1
      #   @overload $1
      #   @overload $1(&example_implementation)
      #     @param example_implementation [Block] The implementation of the example.
      #   @overload $1(doc_string, *metadata_keys, metadata={})
      #     @param doc_string [String] The example's doc string.
      #     @param metadata [Hash] Metadata for the example.
      #     @param metadata_keys [Array<Symbol>] Metadata tags for the example.
      #       Will be transformed into hash entries with `true` values.
      #   @overload $1(doc_string, *metadata_keys, metadata={}, &example_implementation)
      #     @param doc_string [String] The example's doc string.
      #     @param metadata [Hash] Metadata for the example.
      #     @param metadata_keys [Array<Symbol>] Metadata tags for the example.
      #       Will be transformed into hash entries with `true` values.
      #     @param example_implementation [Block] The implementation of the example.
      #   @yield [Example] the example object
      #   @example
      #     $1 do
      #     end
      #
      #     $1 "does something" do
      #     end
      #
      #     $1 "does something", :slow, :uses_js do
      #     end
      #
      #     $1 "does something", :with => 'additional metadata' do
      #     end
      #
      #     $1 "does something" do |ex|
      #       # ex is the Example object that contains metadata about the example
      #     end
      def self.define_example_method(name, extra_options={})
        idempotently_define_singleton_method(name) do |*all_args, &block|
          desc, *args = *all_args

          options = Metadata.build_hash_from(args)
          options.update(:skip => RSpec::Core::Pending::NOT_YET_IMPLEMENTED) unless block
          options.update(extra_options)

          RSpec::Core::Example.new(self, desc, options, block)
        end
      end

      # Defines an example within a group.
      define_example_method :example
      # Defines an example within a group.
      # This is the primary API to define a code example.
      define_example_method :it
      # Defines an example within a group.
      # Useful for when your docstring does not read well off of `it`.
      # @example
      #  RSpec.describe MyClass do
      #    specify "#do_something is deprecated" do
      #      # ...
      #    end
      #  end
      define_example_method :specify

      # Shortcut to define an example with `:focus => true`.
      # @see example
      define_example_method :focus,    :focus => true
      # Shortcut to define an example with `:focus => true`.
      # @see example
      define_example_method :fexample, :focus => true
      # Shortcut to define an example with `:focus => true`.
      # @see example
      define_example_method :fit,      :focus => true
      # Shortcut to define an example with `:focus => true`.
      # @see example
      define_example_method :fspecify, :focus => true
      # Shortcut to define an example with `:skip => 'Temporarily skipped with xexample'`.
      # @see example
      define_example_method :xexample, :skip => 'Temporarily skipped with xexample'
      # Shortcut to define an example with `:skip => 'Temporarily skipped with xit'`.
      # @see example
      define_example_method :xit,      :skip => 'Temporarily skipped with xit'
      # Shortcut to define an example with `:skip => 'Temporarily skipped with xspecify'`.
      # @see example
      define_example_method :xspecify, :skip => 'Temporarily skipped with xspecify'
      # Shortcut to define an example with `:skip => true`
      # @see example
      define_example_method :skip,     :skip => true
      # Shortcut to define an example with `:pending => true`
      # @see example
      define_example_method :pending,  :pending => true

      # @!endgroup

      # @!group Defining Example Groups

      # @private
      # @macro [attach] define_example_group_method
      #   @!scope class
      #   @overload $1
      #   @overload $1(&example_group_definition)
      #     @param example_group_definition [Block] The definition of the example group.
      #   @overload $1(doc_string, *metadata_keys, metadata={}, &example_implementation)
      #     @param doc_string [String] The group's doc string.
      #     @param metadata [Hash] Metadata for the group.
      #     @param metadata_keys [Array<Symbol>] Metadata tags for the group.
      #       Will be transformed into hash entries with `true` values.
      #     @param example_group_definition [Block] The definition of the example group.
      #
      #   Generates a subclass of this example group which inherits
      #   everything except the examples themselves.
      #
      #   @example
      #
      #     RSpec.describe "something" do # << This describe method is defined in
      #                                   # << RSpec::Core::DSL, included in the
      #                                   # << global namespace (optional)
      #       before do
      #         do_something_before
      #       end
      #
      #       let(:thing) { Thing.new }
      #
      #       $1 "attribute (of something)" do
      #         # examples in the group get the before hook
      #         # declared above, and can access `thing`
      #       end
      #     end
      #
      # @see DSL#describe
      def self.define_example_group_method(name, metadata={})
        idempotently_define_singleton_method(name) do |*args, &example_group_block|
          thread_data = RSpec::Support.thread_local_data
          top_level   = self == ExampleGroup

          registration_collection =
            if top_level
              if thread_data[:in_example_group]
                raise "Creating an isolated context from within a context is " \
                      "not allowed. Change `RSpec.#{name}` to `#{name}` or " \
                      "move this to a top-level scope."
              end

              thread_data[:in_example_group] = true
              RSpec.world.example_groups
            else
              children
            end

          begin
            description = args.shift
            combined_metadata = metadata.dup
            combined_metadata.merge!(args.pop) if args.last.is_a? Hash
            args << combined_metadata

            subclass(self, description, args, registration_collection, &example_group_block)
          ensure
            thread_data.delete(:in_example_group) if top_level
          end
        end

        RSpec::Core::DSL.expose_example_group_alias(name)
      end

      define_example_group_method :example_group

      # An alias of `example_group`. Generally used when grouping examples by a
      # thing you are describing (e.g. an object, class or method).
      # @see example_group
      define_example_group_method :describe

      # An alias of `example_group`. Generally used when grouping examples
      # contextually (e.g. "with xyz", "when xyz" or "if xyz").
      # @see example_group
      define_example_group_method :context

      # Shortcut to temporarily make an example group skipped.
      # @see example_group
      define_example_group_method :xdescribe, :skip => "Temporarily skipped with xdescribe"

      # Shortcut to temporarily make an example group skipped.
      # @see example_group
      define_example_group_method :xcontext,  :skip => "Temporarily skipped with xcontext"

      # Shortcut to define an example group with `:focus => true`.
      # @see example_group
      define_example_group_method :fdescribe, :focus => true

      # Shortcut to define an example group with `:focus => true`.
      # @see example_group
      define_example_group_method :fcontext,  :focus => true

      # @!endgroup

      # @!group Including Shared Example Groups

      # @private
      # @macro [attach] define_nested_shared_group_method
      #   @!scope class
      #
      #   @see SharedExampleGroup
      def self.define_nested_shared_group_method(new_name, report_label="it should behave like")
        idempotently_define_singleton_method(new_name) do |name, *args, &customization_block|
          # Pass :caller so the :location metadata is set properly.
          # Otherwise, it'll be set to the next line because that's
          # the block's source_location.
          group = example_group("#{report_label} #{name}", :caller => (the_caller = caller)) do
            find_and_eval_shared("examples", name, the_caller.first, *args, &customization_block)
          end
          group.metadata[:shared_group_name] = name
          group
        end
      end

      # Generates a nested example group and includes the shared content
      # mapped to `name` in the nested group.
      define_nested_shared_group_method :it_behaves_like, "behaves like"
      # Generates a nested example group and includes the shared content
      # mapped to `name` in the nested group.
      define_nested_shared_group_method :it_should_behave_like

      # Includes shared content mapped to `name` directly in the group in which
      # it is declared, as opposed to `it_behaves_like`, which creates a nested
      # group. If given a block, that block is also eval'd in the current
      # context.
      #
      # @see SharedExampleGroup
      def self.include_context(name, *args, &block)
        find_and_eval_shared("context", name, caller.first, *args, &block)
      end

      # Includes shared content mapped to `name` directly in the group in which
      # it is declared, as opposed to `it_behaves_like`, which creates a nested
      # group. If given a block, that block is also eval'd in the current
      # context.
      #
      # @see SharedExampleGroup
      def self.include_examples(name, *args, &block)
        find_and_eval_shared("examples", name, caller.first, *args, &block)
      end

      # Clear memoized values when adding/removing examples
      # @private
      def self.reset_memoized
        @descendant_filtered_examples = nil
        @_descendants = nil
        @parent_groups = nil
        @declaration_locations = nil
      end

      # Adds an example to the example group
      def self.add_example(example)
        reset_memoized
        examples << example
      end

      # Removes an example from the example group
      def self.remove_example(example)
        reset_memoized
        examples.delete example
      end

      # @private
      def self.find_and_eval_shared(label, name, inclusion_location, *args, &customization_block)
        shared_module = RSpec.world.shared_example_group_registry.find(parent_groups, name)

        unless shared_module
          raise ArgumentError, "Could not find shared #{label} #{name.inspect}"
        end

        shared_module.include_in(
          self, Metadata.relative_path(inclusion_location),
          args, customization_block
        )
      end

      # @!endgroup

      # @private
      def self.subclass(parent, description, args, registration_collection, &example_group_block)
        subclass = Class.new(parent)
        subclass.set_it_up(description, args, registration_collection, &example_group_block)
        subclass.module_exec(&example_group_block) if example_group_block

        # The LetDefinitions module must be included _after_ other modules
        # to ensure that it takes precedence when there are name collisions.
        # Thus, we delay including it until after the example group block
        # has been eval'd.
        MemoizedHelpers.define_helpers_on(subclass)

        subclass
      end

      # @private
      def self.set_it_up(description, args, registration_collection, &example_group_block)
        # Ruby 1.9 has a bug that can lead to infinite recursion and a
        # SystemStackError if you include a module in a superclass after
        # including it in a subclass: https://gist.github.com/845896
        # To prevent this, we must include any modules in
        # RSpec::Core::ExampleGroup before users create example groups and have
        # a chance to include the same module in a subclass of
        # RSpec::Core::ExampleGroup. So we need to configure example groups
        # here.
        ensure_example_groups_are_configured

        # Register the example with the group before creating the metadata hash.
        # This is necessary since creating the metadata hash triggers
        # `when_first_matching_example_defined` callbacks, in which users can
        # load RSpec support code which defines hooks. For that to work, the
        # examples and example groups must be registered at the time the
        # support code is called or be defined afterwards.
        # Begin defined beforehand but registered afterwards causes hooks to
        # not be applied where they should.
        registration_collection << self

        @user_metadata = Metadata.build_hash_from(args)

        @metadata = Metadata::ExampleGroupHash.create(
          superclass_metadata, @user_metadata,
          superclass.method(:next_runnable_index_for),
          description, *args, &example_group_block
        )
        ExampleGroups.assign_const(self)

        @currently_executing_a_context_hook = false

        RSpec.configuration.configure_group(self)
      end

      # @private
      def self.examples
        @examples ||= []
      end

      # @private
      def self.filtered_examples
        RSpec.world.filtered_examples[self]
      end

      # @private
      def self.descendant_filtered_examples
        @descendant_filtered_examples ||= filtered_examples +
          FlatMap.flat_map(children, &:descendant_filtered_examples)
      end

      # @private
      def self.children
        @children ||= []
      end

      # @private
      # Traverses the tree of groups, starting with `self`, then the children, recursively.
      # Halts the traversal of a branch of the tree as soon as the passed block returns true.
      # Note that siblings groups and their sub-trees will continue to be explored.
      # This is intended to make it easy to find the top-most group that satisfies some
      # condition.
      def self.traverse_tree_until(&block)
        return if yield self

        children.each do |child|
          child.traverse_tree_until(&block)
        end
      end

      # @private
      def self.next_runnable_index_for(file)
        if self == ExampleGroup
          # We add 1 so the ids start at 1 instead of 0. This is
          # necessary for this branch (but not for the other one)
          # because we register examples and groups with the
          # `children` and `examples` collection BEFORE this
          # method is called as part of metadata hash creation,
          # but the example group is recorded with
          # `RSpec.world.example_group_counts_by_spec_file` AFTER
          # the metadata hash is created and the group is returned
          # to the caller.
          RSpec.world.num_example_groups_defined_in(file) + 1
        else
          children.count + examples.count
        end
      end

      # @private
      def self.descendants
        @_descendants ||= [self] + FlatMap.flat_map(children, &:descendants)
      end

      ## @private
      def self.parent_groups
        @parent_groups ||= ancestors.select { |a| a < RSpec::Core::ExampleGroup }
      end

      # @private
      def self.top_level?
        superclass == ExampleGroup
      end

      # @private
      def self.ensure_example_groups_are_configured
        unless defined?(@@example_groups_configured)
          RSpec.configuration.configure_mock_framework
          RSpec.configuration.configure_expectation_framework
          # rubocop:disable Style/ClassVars
          @@example_groups_configured = true
          # rubocop:enable Style/ClassVars
        end
      end

      # @private
      def self.before_context_ivars
        @before_context_ivars ||= {}
      end

      # @private
      def self.store_before_context_ivars(example_group_instance)
        each_instance_variable_for_example(example_group_instance) do |ivar|
          before_context_ivars[ivar] = example_group_instance.instance_variable_get(ivar)
        end
      end

      # Returns true if a `before(:context)` or `after(:context)`
      # hook is currently executing.
      def self.currently_executing_a_context_hook?
        @currently_executing_a_context_hook
      end

      # @private
      def self.run_before_context_hooks(example_group_instance)
        set_ivars(example_group_instance, superclass_before_context_ivars)

        @currently_executing_a_context_hook = true

        ContextHookMemoized::Before.isolate_for_context_hook(example_group_instance) do
          hooks.run(:before, :context, example_group_instance)
        end
      ensure
        store_before_context_ivars(example_group_instance)
        @currently_executing_a_context_hook = false
      end

      if RUBY_VERSION.to_f >= 1.9
        # @private
        def self.superclass_before_context_ivars
          superclass.before_context_ivars
        end
      else # 1.8.7
        # :nocov:
        # @private
        def self.superclass_before_context_ivars
          if superclass.respond_to?(:before_context_ivars)
            superclass.before_context_ivars
          else
            # `self` must be the singleton class of an ExampleGroup instance.
            # On 1.8.7, the superclass of a singleton class of an instance of A
            # is A's singleton class. On 1.9+, it's A. On 1.8.7, the first ancestor
            # is A, so we can mirror 1.8.7's behavior here. Note that we have to
            # search for the first that responds to `before_context_ivars`
            # in case a module has been included in the singleton class.
            ancestors.find { |a| a.respond_to?(:before_context_ivars) }.before_context_ivars
          end
        end
        # :nocov:
      end

      # @private
      def self.run_after_context_hooks(example_group_instance)
        set_ivars(example_group_instance, before_context_ivars)

        @currently_executing_a_context_hook = true

        ContextHookMemoized::After.isolate_for_context_hook(example_group_instance) do
          hooks.run(:after, :context, example_group_instance)
        end
      ensure
        before_context_ivars.clear
        @currently_executing_a_context_hook = false
      end

      # Runs all the examples in this group.
      def self.run(reporter=RSpec::Core::NullReporter)
        return if RSpec.world.wants_to_quit
        reporter.example_group_started(self)

        should_run_context_hooks = descendant_filtered_examples.any?
        begin
          run_before_context_hooks(new('before(:context) hook')) if should_run_context_hooks
          result_for_this_group = run_examples(reporter)
          results_for_descendants = ordering_strategy.order(children).map { |child| child.run(reporter) }.all?
          result_for_this_group && results_for_descendants
        rescue Pending::SkipDeclaredInExample => ex
          for_filtered_examples(reporter) { |example| example.skip_with_exception(reporter, ex) }
          true
        rescue Support::AllExceptionsExceptOnesWeMustNotRescue => ex
          for_filtered_examples(reporter) { |example| example.fail_with_exception(reporter, ex) }
          RSpec.world.wants_to_quit = true if reporter.fail_fast_limit_met?
          false
        ensure
          run_after_context_hooks(new('after(:context) hook')) if should_run_context_hooks
          reporter.example_group_finished(self)
        end
      end

      # @private
      def self.ordering_strategy
        order = metadata.fetch(:order, :global)
        registry = RSpec.configuration.ordering_registry

        registry.fetch(order) do
          warn <<-WARNING.gsub(/^ +\|/, '')
            |WARNING: Ignoring unknown ordering specified using `:order => #{order.inspect}` metadata.
            |         Falling back to configured global ordering.
            |         Unrecognized ordering specified at: #{location}
          WARNING

          registry.fetch(:global)
        end
      end

      # @private
      def self.run_examples(reporter)
        ordering_strategy.order(filtered_examples).map do |example|
          next if RSpec.world.wants_to_quit
          instance = new(example.inspect_output)
          set_ivars(instance, before_context_ivars)
          succeeded = example.run(instance, reporter)
          if !succeeded && reporter.fail_fast_limit_met?
            RSpec.world.wants_to_quit = true
          end
          succeeded
        end.all?
      end

      # @private
      def self.for_filtered_examples(reporter, &block)
        filtered_examples.each(&block)

        children.each do |child|
          reporter.example_group_started(child)
          child.for_filtered_examples(reporter, &block)
          reporter.example_group_finished(child)
        end
        false
      end

      # @private
      def self.declaration_locations
        @declaration_locations ||= [Metadata.location_tuple_from(metadata)] +
          examples.map { |e| Metadata.location_tuple_from(e.metadata) } +
          FlatMap.flat_map(children, &:declaration_locations)
      end

      # @return [String] the unique id of this example group. Pass
      #   this at the command line to re-run this exact example group.
      def self.id
        Metadata.id_from(metadata)
      end

      # @private
      def self.top_level_description
        parent_groups.last.description
      end

      # @private
      def self.set_ivars(instance, ivars)
        ivars.each { |name, value| instance.instance_variable_set(name, value) }
      end

      if RUBY_VERSION.to_f < 1.9
        # :nocov:
        # @private
        INSTANCE_VARIABLE_TO_IGNORE = '@__inspect_output'.freeze
        # :nocov:
      else
        # @private
        INSTANCE_VARIABLE_TO_IGNORE = :@__inspect_output
      end

      # @private
      def self.each_instance_variable_for_example(group)
        group.instance_variables.each do |ivar|
          yield ivar unless ivar == INSTANCE_VARIABLE_TO_IGNORE
        end
      end

      def initialize(inspect_output=nil)
        @__inspect_output = inspect_output || '(no description provided)'
        super() # no args get passed
      end

      # @private
      def inspect
        "#<#{self.class} #{@__inspect_output}>"
      end

      unless method_defined?(:singleton_class) # for 1.8.7
        # :nocov:
        # @private
        def singleton_class
          class << self; self; end
        end
        # :nocov:
      end

      # @private
      def self.update_inherited_metadata(updates)
        metadata.update(updates) do |key, existing_group_value, new_inherited_value|
          @user_metadata.key?(key) ? existing_group_value : new_inherited_value
        end

        RSpec.configuration.configure_group(self)
        examples.each { |ex| ex.update_inherited_metadata(updates) }
        children.each { |group| group.update_inherited_metadata(updates) }
      end

      # Raised when an RSpec API is called in the wrong scope, such as `before`
      # being called from within an example rather than from within an example
      # group block.
      WrongScopeError = Class.new(NoMethodError)

      def self.method_missing(name, *args)
        if method_defined?(name)
          raise WrongScopeError,
                "`#{name}` is not available on an example group (e.g. a " \
                "`describe` or `context` block). It is only available from " \
                "within individual examples (e.g. `it` blocks) or from " \
                "constructs that run in the scope of an example (e.g. " \
                "`before`, `let`, etc)."
        end

        super
      end
      private_class_method :method_missing

    private

      def method_missing(name, *args)
        if self.class.respond_to?(name)
          raise WrongScopeError,
                "`#{name}` is not available from within an example (e.g. an " \
                "`it` block) or from constructs that run in the scope of an " \
                "example (e.g. `before`, `let`, etc). It is only available " \
                "on an example group (e.g. a `describe` or `context` block)."
        end

        super
      end
    end
    # rubocop:enable Metrics/ClassLength

    # @private
    # Unnamed example group used by `SuiteHookContext`.
    class AnonymousExampleGroup < ExampleGroup
      def self.metadata
        {}
      end
    end

    # Contains information about the inclusion site of a shared example group.
    class SharedExampleGroupInclusionStackFrame
      # @return [String] the name of the shared example group
      attr_reader :shared_group_name
      # @return [String] the location where the shared example was included
      attr_reader :inclusion_location

      def initialize(shared_group_name, inclusion_location)
        @shared_group_name  = shared_group_name
        @inclusion_location = inclusion_location
      end

      # @return [String] The {#inclusion_location}, formatted for display by a formatter.
      def formatted_inclusion_location
        @formatted_inclusion_location ||= begin
          RSpec.configuration.backtrace_formatter.backtrace_line(
            inclusion_location.sub(/(:\d+):in .+$/, '\1')
          )
        end
      end

      # @return [String] Description of this stack frame, in the form used by
      #   RSpec's built-in formatters.
      def description
        @description ||= "Shared Example Group: #{shared_group_name.inspect} " \
          "called from #{formatted_inclusion_location}"
      end

      # @private
      def self.current_backtrace
        shared_example_group_inclusions.reverse
      end

      # @private
      def self.with_frame(name, location)
        current_stack = shared_example_group_inclusions
        if current_stack.any? { |frame| frame.shared_group_name == name }
          raise ArgumentError, "can't include shared examples recursively"
        else
          current_stack << new(name, location)
          yield
        end
      ensure
        current_stack.pop
      end

      # @private
      def self.shared_example_group_inclusions
        RSpec::Support.thread_local_data[:shared_example_group_inclusions] ||= []
      end
    end
  end

  # @private
  #
  # Namespace for the example group subclasses generated by top-level
  # `describe`.
  module ExampleGroups
    extend Support::RecursiveConstMethods

    def self.assign_const(group)
      base_name   = base_name_for(group)
      const_scope = constant_scope_for(group)
      name        = disambiguate(base_name, const_scope)

      const_scope.const_set(name, group)
    end

    def self.constant_scope_for(group)
      const_scope = group.superclass
      const_scope = self if const_scope == ::RSpec::Core::ExampleGroup
      const_scope
    end

    def self.remove_all_constants
      constants.each do |constant|
        __send__(:remove_const, constant)
      end
    end

    def self.base_name_for(group)
      return "Anonymous".dup if group.description.empty?

      # Convert to CamelCase.
      name = ' ' + group.description
      name.gsub!(/[^0-9a-zA-Z]+([0-9a-zA-Z])/) do
        match = ::Regexp.last_match[1]
        match.upcase!
        match
      end

      name.lstrip!                # Remove leading whitespace
      name.gsub!(/\W/, ''.freeze) # JRuby, RBX and others don't like non-ascii in const names

      # Ruby requires first const letter to be A-Z. Use `Nested`
      # as necessary to enforce that.
      name.gsub!(/\A([^A-Z]|\z)/, 'Nested\1'.freeze)

      name
    end

    if RUBY_VERSION == '1.9.2'
      # :nocov:
      class << self
        alias _base_name_for base_name_for
        def base_name_for(group)
          _base_name_for(group) + '_'
        end
      end
      private_class_method :_base_name_for
      # :nocov:
    end

    def self.disambiguate(name, const_scope)
      return name unless const_defined_on?(const_scope, name)

      # Add a trailing number if needed to disambiguate from an existing
      # constant.
      name << "_2"
      name.next! while const_defined_on?(const_scope, name)
      name
    end
  end
end
