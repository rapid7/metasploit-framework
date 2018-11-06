module RSpec
  module Core
    # Wrapper for an instance of a subclass of {ExampleGroup}. An instance of
    # `RSpec::Core::Example` is returned by example definition methods
    # such as {ExampleGroup.it it} and is yielded to the {ExampleGroup.it it},
    # {Hooks#before before}, {Hooks#after after}, {Hooks#around around},
    # {MemoizedHelpers::ClassMethods#let let} and
    # {MemoizedHelpers::ClassMethods#subject subject} blocks.
    #
    # This allows us to provide rich metadata about each individual
    # example without adding tons of methods directly to the ExampleGroup
    # that users may inadvertently redefine.
    #
    # Useful for configuring logging and/or taking some action based
    # on the state of an example's metadata.
    #
    # @example
    #
    #     RSpec.configure do |config|
    #       config.before do |example|
    #         log example.description
    #       end
    #
    #       config.after do |example|
    #         log example.description
    #       end
    #
    #       config.around do |example|
    #         log example.description
    #         example.run
    #       end
    #     end
    #
    #     shared_examples "auditable" do
    #       it "does something" do
    #         log "#{example.full_description}: #{auditable.inspect}"
    #         auditable.should do_something
    #       end
    #     end
    #
    # @see ExampleGroup
    # @note Example blocks are evaluated in the context of an instance
    #   of an `ExampleGroup`, not in the context of an instance of `Example`.
    class Example
      # @private
      #
      # Used to define methods that delegate to this example's metadata.
      def self.delegate_to_metadata(key)
        define_method(key) { @metadata[key] }
      end

      # @return [ExecutionResult] represents the result of running this example.
      delegate_to_metadata :execution_result
      # @return [String] the relative path to the file where this example was
      #   defined.
      delegate_to_metadata :file_path
      # @return [String] the full description (including the docstrings of
      #   all parent example groups).
      delegate_to_metadata :full_description
      # @return [String] the exact source location of this example in a form
      #   like `./path/to/spec.rb:17`
      delegate_to_metadata :location
      # @return [Boolean] flag that indicates that the example is not expected
      #   to pass. It will be run and will either have a pending result (if a
      #   failure occurs) or a failed result (if no failure occurs).
      delegate_to_metadata :pending
      # @return [Boolean] flag that will cause the example to not run.
      #   The {ExecutionResult} status will be `:pending`.
      delegate_to_metadata :skip

      # Returns the string submitted to `example` or its aliases (e.g.
      # `specify`, `it`, etc). If no string is submitted (e.g.
      # `it { is_expected.to do_something }`) it returns the message generated
      # by the matcher if there is one, otherwise returns a message including
      # the location of the example.
      def description
        description = if metadata[:description].to_s.empty?
                        location_description
                      else
                        metadata[:description]
                      end

        RSpec.configuration.format_docstrings_block.call(description)
      end

      # Returns a description of the example that always includes the location.
      def inspect_output
        inspect_output = "\"#{description}\""
        unless metadata[:description].to_s.empty?
          inspect_output += " (#{location})"
        end
        inspect_output
      end

      # Returns the location-based argument that can be passed to the `rspec` command to rerun this example.
      def location_rerun_argument
        @location_rerun_argument ||= begin
          loaded_spec_files = RSpec.configuration.loaded_spec_files

          Metadata.ascending(metadata) do |meta|
            return meta[:location] if loaded_spec_files.include?(meta[:absolute_file_path])
          end
        end
      end

      # Returns the location-based argument that can be passed to the `rspec` command to rerun this example.
      #
      # @deprecated Use {#location_rerun_argument} instead.
      # @note If there are multiple examples identified by this location, they will use {#id}
      #   to rerun instead, but this method will still return the location (that's why it is deprecated!).
      def rerun_argument
        location_rerun_argument
      end

      # @return [String] the unique id of this example. Pass
      #   this at the command line to re-run this exact example.
      def id
        @id ||= Metadata.id_from(metadata)
      end

      # @private
      def self.parse_id(id)
        # http://rubular.com/r/OMZSAPcAfn
        id.match(/\A(.*?)(?:\[([\d\s:,]+)\])?\z/).captures
      end

      # Duplicates the example and overrides metadata with the provided
      # hash.
      #
      # @param metadata_overrides [Hash] the hash to override the example metadata
      # @return [Example] a duplicate of the example with modified metadata
      def duplicate_with(metadata_overrides={})
        new_metadata = metadata.clone.merge(metadata_overrides)

        RSpec::Core::Metadata::RESERVED_KEYS.each do |reserved_key|
          new_metadata.delete reserved_key
        end

        # don't clone the example group because the new example
        # must belong to the same example group (not a clone).
        #
        # block is nil in new_metadata so we have to get it from metadata.
        Example.new(example_group, description.clone,
                    new_metadata, metadata[:block])
      end

      # @private
      def update_inherited_metadata(updates)
        metadata.update(updates) do |_key, existing_example_value, _new_inherited_value|
          existing_example_value
        end
      end

      # @attr_reader
      #
      # Returns the first exception raised in the context of running this
      # example (nil if no exception is raised).
      attr_reader :exception

      # @attr_reader
      #
      # Returns the metadata object associated with this example.
      attr_reader :metadata

      # @attr_reader
      # @private
      #
      # Returns the example_group_instance that provides the context for
      # running this example.
      attr_reader :example_group_instance

      # @attr
      # @private
      attr_accessor :clock

      # Creates a new instance of Example.
      # @param example_group_class [Class] the subclass of ExampleGroup in which
      #   this Example is declared
      # @param description [String] the String passed to the `it` method (or
      #   alias)
      # @param user_metadata [Hash] additional args passed to `it` to be used as
      #   metadata
      # @param example_block [Proc] the block of code that represents the
      #   example
      # @api private
      def initialize(example_group_class, description, user_metadata, example_block=nil)
        @example_group_class = example_group_class
        @example_block       = example_block

        # Register the example with the group before creating the metadata hash.
        # This is necessary since creating the metadata hash triggers
        # `when_first_matching_example_defined` callbacks, in which users can
        # load RSpec support code which defines hooks. For that to work, the
        # examples and example groups must be registered at the time the
        # support code is called or be defined afterwards.
        # Begin defined beforehand but registered afterwards causes hooks to
        # not be applied where they should.
        example_group_class.examples << self

        @metadata = Metadata::ExampleHash.create(
          @example_group_class.metadata, user_metadata,
          example_group_class.method(:next_runnable_index_for),
          description, example_block
        )

        # This should perhaps be done in `Metadata::ExampleHash.create`,
        # but the logic there has no knowledge of `RSpec.world` and we
        # want to keep it that way. It's easier to just assign it here.
        @metadata[:last_run_status] = RSpec.configuration.last_run_statuses[id]

        @example_group_instance = @exception = nil
        @clock = RSpec::Core::Time
        @reporter = RSpec::Core::NullReporter
      end

      # Provide a human-readable representation of this class
      def inspect
        "#<#{self.class.name} #{description.inspect}>"
      end
      alias to_s inspect

      # @return [RSpec::Core::Reporter] the current reporter for the example
      attr_reader :reporter

      # Returns the example group class that provides the context for running
      # this example.
      def example_group
        @example_group_class
      end

      alias_method :pending?, :pending
      alias_method :skipped?, :skip

      # @api private
      # instance_execs the block passed to the constructor in the context of
      # the instance of {ExampleGroup}.
      # @param example_group_instance the instance of an ExampleGroup subclass
      def run(example_group_instance, reporter)
        @example_group_instance = example_group_instance
        @reporter = reporter
        RSpec.configuration.configure_example(self, hooks)
        RSpec.current_example = self

        start(reporter)
        Pending.mark_pending!(self, pending) if pending?

        begin
          if skipped?
            Pending.mark_pending! self, skip
          elsif !RSpec.configuration.dry_run?
            with_around_and_singleton_context_hooks do
              begin
                run_before_example
                @example_group_instance.instance_exec(self, &@example_block)

                if pending?
                  Pending.mark_fixed! self

                  raise Pending::PendingExampleFixedError,
                        'Expected example to fail since it is pending, but it passed.',
                        [location]
                end
              rescue Pending::SkipDeclaredInExample => _
                # The "=> _" is normally useless but on JRuby it is a workaround
                # for a bug that prevents us from getting backtraces:
                # https://github.com/jruby/jruby/issues/4467
                #
                # no-op, required metadata has already been set by the `skip`
                # method.
              rescue AllExceptionsExcludingDangerousOnesOnRubiesThatAllowIt => e
                set_exception(e)
              ensure
                run_after_example
              end
            end
          end
        rescue Support::AllExceptionsExceptOnesWeMustNotRescue => e
          set_exception(e)
        ensure
          @example_group_instance = nil # if you love something... let it go
        end

        finish(reporter)
      ensure
        execution_result.ensure_timing_set(clock)
        RSpec.current_example = nil
      end

      if RSpec::Support::Ruby.jruby? || RUBY_VERSION.to_f < 1.9
        # :nocov:
        # For some reason, rescuing `Support::AllExceptionsExceptOnesWeMustNotRescue`
        # in place of `Exception` above can cause the exit status to be the wrong
        # thing. I have no idea why. See:
        # https://github.com/rspec/rspec-core/pull/2063#discussion_r38284978
        # @private
        AllExceptionsExcludingDangerousOnesOnRubiesThatAllowIt = Exception
        # :nocov:
      else
        # @private
        AllExceptionsExcludingDangerousOnesOnRubiesThatAllowIt = Support::AllExceptionsExceptOnesWeMustNotRescue
      end

      # Wraps both a `Proc` and an {Example} for use in {Hooks#around
      # around} hooks. In around hooks we need to yield this special
      # kind of object (rather than the raw {Example}) because when
      # there are multiple `around` hooks we have to wrap them recursively.
      #
      # @example
      #
      #     RSpec.configure do |c|
      #       c.around do |ex| # Procsy which wraps the example
      #         if ex.metadata[:key] == :some_value && some_global_condition
      #           raise "some message"
      #         end
      #         ex.run         # run delegates to ex.call.
      #       end
      #     end
      #
      # @note This class also exposes the instance methods of {Example},
      #   proxying them through to the wrapped {Example} instance.
      class Procsy
        # The {Example} instance.
        attr_reader :example

        Example.public_instance_methods(false).each do |name|
          name_sym = name.to_sym
          next if name_sym == :run || name_sym == :inspect || name_sym == :to_s

          define_method(name) { |*a, &b| @example.__send__(name, *a, &b) }
        end

        Proc.public_instance_methods(false).each do |name|
          name_sym = name.to_sym
          next if name_sym == :call || name_sym == :inspect || name_sym == :to_s || name_sym == :to_proc

          define_method(name) { |*a, &b| @proc.__send__(name, *a, &b) }
        end

        # Calls the proc and notes that the example has been executed.
        def call(*args, &block)
          @executed = true
          @proc.call(*args, &block)
        end
        alias run call

        # Provides a wrapped proc that will update our `executed?` state when
        # executed.
        def to_proc
          method(:call).to_proc
        end

        def initialize(example, &block)
          @example  = example
          @proc     = block
          @executed = false
        end

        # @private
        def wrap(&block)
          self.class.new(example, &block)
        end

        # Indicates whether or not the around hook has executed the example.
        def executed?
          @executed
        end

        # @private
        def inspect
          @example.inspect.gsub('Example', 'ExampleProcsy')
        end
      end

      # @private
      #
      # The exception that will be displayed to the user -- either the failure of
      # the example or the `pending_exception` if the example is pending.
      def display_exception
        @exception || execution_result.pending_exception
      end

      # @private
      #
      # Assigns the exception that will be displayed to the user -- either the failure of
      # the example or the `pending_exception` if the example is pending.
      def display_exception=(ex)
        if pending? && !(Pending::PendingExampleFixedError === ex)
          @exception = nil
          execution_result.pending_fixed = false
          execution_result.pending_exception = ex
        else
          @exception = ex
        end
      end

      # rubocop:disable Naming/AccessorMethodName

      # @private
      #
      # Used internally to set an exception in an after hook, which
      # captures the exception but doesn't raise it.
      def set_exception(exception)
        return self.display_exception = exception unless display_exception

        unless RSpec::Core::MultipleExceptionError === display_exception
          self.display_exception = RSpec::Core::MultipleExceptionError.new(display_exception)
        end

        display_exception.add exception
      end

      # @private
      #
      # Used to set the exception when `aggregate_failures` fails.
      def set_aggregate_failures_exception(exception)
        return set_exception(exception) unless display_exception

        exception = RSpec::Core::MultipleExceptionError::InterfaceTag.for(exception)
        exception.add display_exception
        self.display_exception = exception
      end

      # rubocop:enable Naming/AccessorMethodName

      # @private
      #
      # Used internally to set an exception and fail without actually executing
      # the example when an exception is raised in before(:context).
      def fail_with_exception(reporter, exception)
        start(reporter)
        set_exception(exception)
        finish(reporter)
      end

      # @private
      #
      # Used internally to skip without actually executing the example when
      # skip is used in before(:context).
      def skip_with_exception(reporter, exception)
        start(reporter)
        Pending.mark_skipped! self, exception.argument
        finish(reporter)
      end

      # @private
      def instance_exec(*args, &block)
        @example_group_instance.instance_exec(*args, &block)
      end

    private

      def hooks
        example_group_instance.singleton_class.hooks
      end

      def with_around_example_hooks
        hooks.run(:around, :example, self) { yield }
      rescue Support::AllExceptionsExceptOnesWeMustNotRescue => e
        set_exception(e)
      end

      def start(reporter)
        reporter.example_started(self)
        execution_result.started_at = clock.now
      end

      def finish(reporter)
        pending_message = execution_result.pending_message

        if @exception
          execution_result.exception = @exception
          record_finished :failed, reporter
          reporter.example_failed self
          false
        elsif pending_message
          execution_result.pending_message = pending_message
          record_finished :pending, reporter
          reporter.example_pending self
          true
        else
          record_finished :passed, reporter
          reporter.example_passed self
          true
        end
      end

      def record_finished(status, reporter)
        execution_result.record_finished(status, clock.now)
        reporter.example_finished(self)
      end

      def run_before_example
        @example_group_instance.setup_mocks_for_rspec
        hooks.run(:before, :example, self)
      end

      def with_around_and_singleton_context_hooks
        singleton_context_hooks_host = example_group_instance.singleton_class
        singleton_context_hooks_host.run_before_context_hooks(example_group_instance)
        with_around_example_hooks { yield }
      ensure
        singleton_context_hooks_host.run_after_context_hooks(example_group_instance)
      end

      def run_after_example
        assign_generated_description if defined?(::RSpec::Matchers)
        hooks.run(:after, :example, self)
        verify_mocks
      ensure
        @example_group_instance.teardown_mocks_for_rspec
      end

      def verify_mocks
        @example_group_instance.verify_mocks_for_rspec if mocks_need_verification?
      rescue Support::AllExceptionsExceptOnesWeMustNotRescue => e
        set_exception(e)
      end

      def mocks_need_verification?
        exception.nil? || execution_result.pending_fixed?
      end

      def assign_generated_description
        if metadata[:description].empty? && (description = generate_description)
          metadata[:description] = description
          metadata[:full_description] += description
        end
      ensure
        RSpec::Matchers.clear_generated_description
      end

      def generate_description
        RSpec::Matchers.generated_description
      rescue Support::AllExceptionsExceptOnesWeMustNotRescue => e
        location_description + " (Got an error when generating description " \
          "from matcher: #{e.class}: #{e.message} -- #{e.backtrace.first})"
      end

      def location_description
        "example at #{location}"
      end

      # Represents the result of executing an example.
      # Behaves like a hash for backwards compatibility.
      class ExecutionResult
        include HashImitatable

        # @return [Symbol] `:passed`, `:failed` or `:pending`.
        attr_accessor :status

        # @return [Exception, nil] The failure, if there was one.
        attr_accessor :exception

        # @return [Time] When the example started.
        attr_accessor :started_at

        # @return [Time] When the example finished.
        attr_accessor :finished_at

        # @return [Float] How long the example took in seconds.
        attr_accessor :run_time

        # @return [String, nil] The reason the example was pending,
        #   or nil if the example was not pending.
        attr_accessor :pending_message

        # @return [Exception, nil] The exception triggered while
        #   executing the pending example. If no exception was triggered
        #   it would no longer get a status of `:pending` unless it was
        #   tagged with `:skip`.
        attr_accessor :pending_exception

        # @return [Boolean] For examples tagged with `:pending`,
        #   this indicates whether or not it now passes.
        attr_accessor :pending_fixed

        alias pending_fixed? pending_fixed

        # @return [Boolean] Indicates if the example was completely skipped
        #   (typically done via `:skip` metadata or the `skip` method). Skipped examples
        #   will have a `:pending` result. A `:pending` result can also come from examples
        #   that were marked as `:pending`, which causes them to be run, and produces a
        #   `:failed` result if the example passes.
        def example_skipped?
          status == :pending && !pending_exception
        end

        # @api private
        # Records the finished status of the example.
        def record_finished(status, finished_at)
          self.status = status
          calculate_run_time(finished_at)
        end

        # @api private
        # Populates finished_at and run_time if it has not yet been set
        def ensure_timing_set(clock)
          calculate_run_time(clock.now) unless finished_at
        end

      private

        def calculate_run_time(finished_at)
          self.finished_at = finished_at
          self.run_time    = (finished_at - started_at).to_f
        end

        # For backwards compatibility we present `status` as a string
        # when presenting the legacy hash interface.
        def hash_for_delegation
          super.tap do |hash|
            hash[:status] &&= status.to_s
          end
        end

        def set_value(name, value)
          value &&= value.to_sym if name == :status
          super(name, value)
        end

        def get_value(name)
          if name == :status
            status.to_s if status
          else
            super
          end
        end

        def issue_deprecation(_method_name, *_args)
          RSpec.deprecate("Treating `metadata[:execution_result]` as a hash",
                          :replacement => "the attributes methods to access the data")
        end
      end
    end

    # @private
    # Provides an execution context for before/after :suite hooks.
    class SuiteHookContext < Example
      def initialize(hook_description, reporter)
        super(AnonymousExampleGroup, hook_description, {})
        @example_group_instance = AnonymousExampleGroup.new
        @reporter = reporter
      end

      # rubocop:disable Naming/AccessorMethodName
      def set_exception(exception)
        reporter.notify_non_example_exception(exception, "An error occurred in #{description}.")
        RSpec.world.wants_to_quit = true
      end
      # rubocop:enable Naming/AccessorMethodName
    end
  end
end
