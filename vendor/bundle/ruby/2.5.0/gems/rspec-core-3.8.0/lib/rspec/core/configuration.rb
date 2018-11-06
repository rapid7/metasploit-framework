RSpec::Support.require_rspec_core "backtrace_formatter"
RSpec::Support.require_rspec_core "ruby_project"
RSpec::Support.require_rspec_core "formatters/deprecation_formatter"
RSpec::Support.require_rspec_core "output_wrapper"

module RSpec
  module Core
    # rubocop:disable Metrics/ClassLength

    # Stores runtime configuration information.
    #
    # Configuration options are loaded from multiple files and joined together
    # with command-line switches and the `SPEC_OPTS` environment variable.
    #
    # Precedence order (where later entries overwrite earlier entries on
    # conflicts):
    #
    #   * Global (`$XDG_CONFIG_HOME/rspec/options`, or `~/.rspec` if it does
    #     not exist)
    #   * Project-specific (`./.rspec`)
    #   * Local (`./.rspec-local`)
    #   * Command-line options
    #   * `SPEC_OPTS`
    #
    # For example, an option set in the local file will override an option set
    # in your global file.
    #
    # The global, project-specific and local files can all be overridden with a
    # separate custom file using the --options command-line parameter.
    #
    # @example Standard settings
    #     RSpec.configure do |c|
    #       c.drb          = true
    #       c.drb_port     = 1234
    #       c.default_path = 'behavior'
    #     end
    #
    # @example Hooks
    #     RSpec.configure do |c|
    #       c.before(:suite)   { establish_connection }
    #       c.before(:example) { log_in_as :authorized }
    #       c.around(:example) { |ex| Database.transaction(&ex) }
    #     end
    #
    # @see RSpec.configure
    # @see Hooks
    class Configuration
      include RSpec::Core::Hooks

      # Module that holds `attr_reader` declarations. It's in a separate
      # module to allow us to override those methods and use `super`.
      # @private
      Readers = Module.new
      include Readers

      # @private
      class MustBeConfiguredBeforeExampleGroupsError < StandardError; end

      # @private
      def self.define_reader(name)
        Readers.class_eval do
          remove_method name if method_defined?(name)
          attr_reader name
        end

        define_method(name) { value_for(name) { super() } }
      end

      # @private
      def self.define_aliases(name, alias_name)
        alias_method alias_name, name
        alias_method "#{alias_name}=", "#{name}="
        define_predicate_for alias_name
      end

      # @private
      def self.define_predicate_for(*names)
        names.each { |name| alias_method "#{name}?", name }
      end

      # @private
      #
      # Invoked by the `add_setting` instance method. Use that method on a
      # `Configuration` instance rather than this class method.
      def self.add_setting(name, opts={})
        raise "Use the instance add_setting method if you want to set a default" if opts.key?(:default)
        attr_writer name
        add_read_only_setting name

        Array(opts[:alias_with]).each do |alias_name|
          define_aliases(name, alias_name)
        end
      end

      # @private
      #
      # As `add_setting` but only add the reader.
      def self.add_read_only_setting(name, opts={})
        raise "Use the instance add_setting method if you want to set a default" if opts.key?(:default)
        define_reader name
        define_predicate_for name
      end

      # @macro [attach] add_setting
      #   @!attribute [rw] $1
      #
      # @macro [attach] define_reader
      #   @!attribute [r] $1

      # @macro add_setting
      # Path to use if no path is provided to the `rspec` command (default:
      # `"spec"`). Allows you to just type `rspec` instead of `rspec spec` to
      # run all the examples in the `spec` directory.
      #
      # @note Other scripts invoking `rspec` indirectly will ignore this
      #   setting.
      # @return [String]
      add_read_only_setting :default_path
      def default_path=(path)
        project_source_dirs << path
        @default_path = path
      end

      # @macro add_setting
      # Run examples over DRb (default: `false`). RSpec doesn't supply the DRb
      # server, but you can use tools like spork.
      # @return [Boolean]
      add_setting :drb

      # @macro add_setting
      # The drb_port (default: nil).
      add_setting :drb_port

      # @macro add_setting
      # Default: `$stderr`.
      add_setting :error_stream

      # Indicates if the DSL has been exposed off of modules and `main`.
      # Default: true
      # @return [Boolean]
      def expose_dsl_globally?
        Core::DSL.exposed_globally?
      end

      # Use this to expose the core RSpec DSL via `Module` and the `main`
      # object. It will be set automatically but you can override it to
      # remove the DSL.
      # Default: true
      def expose_dsl_globally=(value)
        if value
          Core::DSL.expose_globally!
          Core::SharedExampleGroup::TopLevelDSL.expose_globally!
        else
          Core::DSL.remove_globally!
          Core::SharedExampleGroup::TopLevelDSL.remove_globally!
        end
      end

      # Determines where deprecation warnings are printed.
      # Defaults to `$stderr`.
      # @return [IO, String] IO or filename to write to
      define_reader :deprecation_stream

      # Determines where deprecation warnings are printed.
      # @param value [IO, String] IO to write to or filename to write to
      def deprecation_stream=(value)
        if @reporter && !value.equal?(@deprecation_stream)
          warn "RSpec's reporter has already been initialized with " \
            "#{deprecation_stream.inspect} as the deprecation stream, so your change to "\
            "`deprecation_stream` will be ignored. You should configure it earlier for " \
            "it to take effect, or use the `--deprecation-out` CLI option. " \
            "(Called from #{CallerFilter.first_non_rspec_line})"
        else
          @deprecation_stream = value
        end
      end

      # @macro define_reader
      # The file path to use for persisting example statuses. Necessary for the
      # `--only-failures` and `--next-failure` CLI options.
      #
      # @overload example_status_persistence_file_path
      #   @return [String] the file path
      # @overload example_status_persistence_file_path=(value)
      #   @param value [String] the file path
      define_reader :example_status_persistence_file_path

      # Sets the file path to use for persisting example statuses. Necessary for the
      # `--only-failures` and `--next-failure` CLI options.
      def example_status_persistence_file_path=(value)
        @example_status_persistence_file_path = value
        clear_values_derived_from_example_status_persistence_file_path
      end

      # @macro define_reader
      # Indicates if the `--only-failures` (or `--next-failure`) flag is being used.
      define_reader :only_failures
      alias_method :only_failures?, :only_failures

      # @private
      def only_failures_but_not_configured?
        only_failures? && !example_status_persistence_file_path
      end

      # @macro add_setting
      # If specified, indicates the number of failures required before cleaning
      # up and exit (default: `nil`).
      add_setting :fail_fast

      # @macro add_setting
      # Prints the formatter output of your suite without running any
      # examples or hooks.
      add_setting :dry_run

      # @macro add_setting
      # The exit code to return if there are any failures (default: 1).
      # @return [Integer]
      add_setting :failure_exit_code

      # @macro add_setting
      # Whether or not to fail when there are no RSpec examples (default: false).
      # @return [Boolean]
      add_setting :fail_if_no_examples

      # @macro define_reader
      # Indicates files configured to be required.
      # @return [Array<String>]
      define_reader :requires

      # @macro define_reader
      # Returns dirs that have been prepended to the load path by the `-I`
      # command line option.
      # @return [Array<String>]
      define_reader :libs

      # @macro add_setting
      # Determines where RSpec will send its output.
      # Default: `$stdout`.
      # @return [IO, String]
      define_reader :output_stream

      # Set the output stream for reporter.
      # @attr value [IO, String] IO to write to or filename to write to, defaults to $stdout
      def output_stream=(value)
        if @reporter && !value.equal?(@output_stream)
          warn "RSpec's reporter has already been initialized with " \
            "#{output_stream.inspect} as the output stream, so your change to "\
            "`output_stream` will be ignored. You should configure it earlier for " \
            "it to take effect. (Called from #{CallerFilter.first_non_rspec_line})"
        else
          @output_stream = value
          output_wrapper.output = @output_stream
        end
      end

      # @macro define_reader
      # Load files matching this pattern (default: `'**{,/*/**}/*_spec.rb'`).
      # @return [String]
      define_reader :pattern

      # Set pattern to match files to load.
      # @attr value [String] the filename pattern to filter spec files by
      def pattern=(value)
        update_pattern_attr :pattern, value
      end

      # @macro define_reader
      # Exclude files matching this pattern.
      # @return [String]
      define_reader :exclude_pattern

      # Set pattern to match files to exclude.
      # @attr value [String] the filename pattern to exclude spec files by
      def exclude_pattern=(value)
        update_pattern_attr :exclude_pattern, value
      end

      # @macro add_setting
      # Specifies which directories contain the source code for your project.
      # When a failure occurs, RSpec looks through the backtrace to find a
      # a line of source to print. It first looks for a line coming from
      # one of the project source directories so that, for example, it prints
      # the expectation or assertion call rather than the source code from
      # the expectation or assertion framework.
      # @return [Array<String>]
      add_setting :project_source_dirs

      # @macro add_setting
      # Report the times for the slowest examples (default: `false`).
      # Use this to specify the number of examples to include in the profile.
      # @return [Boolean]
      add_setting :profile_examples

      # @macro add_setting
      # Run all examples if none match the configured filters
      # (default: `false`).
      # @deprecated Use {#filter_run_when_matching} instead for the specific
      #   filters that you want to be ignored if none match.
      add_setting :run_all_when_everything_filtered

      # @macro add_setting
      # Color to use to indicate success.  Defaults to `:green` but can be set
      # to one of the following: `[:black, :white, :red, :green, :yellow,
      # :blue, :magenta, :cyan]`
      # @return [Symbol]
      add_setting :success_color

      # @macro add_setting
      # Color to use to print pending examples.  Defaults to `:yellow` but can
      # be set to one of the following: `[:black, :white, :red, :green,
      # :yellow, :blue, :magenta, :cyan]`
      # @return [Symbol]
      add_setting :pending_color

      # @macro add_setting
      # Color to use to indicate failure.  Defaults to `:red` but can be set to
      # one of the following: `[:black, :white, :red, :green, :yellow, :blue,
      # :magenta, :cyan]`
      # @return [Symbol]
      add_setting :failure_color

      # @macro add_setting
      # The default output color. Defaults to `:white` but can be set to one of
      # the following: `[:black, :white, :red, :green, :yellow, :blue,
      # :magenta, :cyan]`
      # @return [Symbol]
      add_setting :default_color

      # @macro add_setting
      # Color used when a pending example is fixed. Defaults to `:blue` but can
      # be set to one of the following: `[:black, :white, :red, :green,
      # :yellow, :blue, :magenta, :cyan]`
      # @return [Symbol]
      add_setting :fixed_color

      # @macro add_setting
      # Color used to print details.  Defaults to `:cyan` but can be set to one
      # of the following: `[:black, :white, :red, :green, :yellow, :blue,
      # :magenta, :cyan]`
      # @return [Symbol]
      add_setting :detail_color

      # @macro add_setting
      # Don't print filter info i.e. "Run options: include {:focus=>true}"
      # (default `false`).
      # return [Boolean]
      add_setting :silence_filter_announcements

      # @deprecated This config option was added in RSpec 2 to pave the way
      #   for this being the default behavior in RSpec 3. Now this option is
      #   a no-op.
      def treat_symbols_as_metadata_keys_with_true_values=(_value)
        RSpec.deprecate(
          "RSpec::Core::Configuration#treat_symbols_as_metadata_keys_with_true_values=",
          :message => "RSpec::Core::Configuration#treat_symbols_as_metadata_keys_with_true_values= " \
                      "is deprecated, it is now set to true as default and " \
                      "setting it to false has no effect."
        )
      end

      # @macro define_reader
      # Configures how RSpec treats metadata passed as part of a shared example
      # group definition. For example, given this shared example group definition:
      #
      #     RSpec.shared_context "uses DB", :db => true do
      #       around(:example) do |ex|
      #         MyORM.transaction(:rollback => true, &ex)
      #       end
      #     end
      #
      # ...there are two ways RSpec can treat the `:db => true` metadata, each
      # of which has a corresponding config option:
      #
      # 1. `:trigger_inclusion`: this shared context will be implicitly included
      #    in any groups (or examples) that have `:db => true` metadata.
      # 2. `:apply_to_host_groups`: the metadata will be inherited by the metadata
      #    hash of all host groups and examples.
      #
      # `:trigger_inclusion` is the legacy behavior from before RSpec 3.5 but should
      # be considered deprecated. Instead, you can explicitly include a group with
      # `include_context`:
      #
      #     RSpec.describe "My model" do
      #       include_context "uses DB"
      #     end
      #
      # ...or you can configure RSpec to include the context based on matching metadata
      # using an API that mirrors configured module inclusion:
      #
      #     RSpec.configure do |rspec|
      #       rspec.include_context "uses DB", :db => true
      #     end
      #
      # `:apply_to_host_groups` is a new feature of RSpec 3.5 and will be the only
      # supported behavior in RSpec 4.
      #
      # @overload shared_context_metadata_behavior
      #   @return [:trigger_inclusion, :apply_to_host_groups] the configured behavior
      # @overload shared_context_metadata_behavior=(value)
      #   @param value [:trigger_inclusion, :apply_to_host_groups] sets the configured behavior
      define_reader :shared_context_metadata_behavior
      # @see shared_context_metadata_behavior
      def shared_context_metadata_behavior=(value)
        case value
        when :trigger_inclusion, :apply_to_host_groups
          @shared_context_metadata_behavior = value
        else
          raise ArgumentError, "Cannot set `RSpec.configuration." \
            "shared_context_metadata_behavior` to `#{value.inspect}`. Only " \
            "`:trigger_inclusion` and `:apply_to_host_groups` are valid values."
        end
      end

      # Record the start time of the spec suite to measure load time.
      # return [Time]
      add_setting :start_time

      # @macro add_setting
      # Use threadsafe options where available.
      # Currently this will place a mutex around memoized values such as let blocks.
      # return [Boolean]
      add_setting :threadsafe

      # @macro add_setting
      # Maximum count of failed source lines to display in the failure reports.
      # (default `10`).
      # return [Integer]
      add_setting :max_displayed_failure_line_count

      # Determines which bisect runner implementation gets used to run subsets
      # of the suite during a bisection. Your choices are:
      #
      #   - `:shell`: Performs a spec run by shelling out, booting RSpec and your
      #     application environment each time. This runner is the most widely
      #     compatible runner, but is not as fast. On platforms that do not
      #     support forking, this is the default.
      #   - `:fork`: Pre-boots RSpec and your application environment in a parent
      #     process, and then forks a child process for each spec run. This runner
      #     tends to be significantly faster than the `:shell` runner but cannot
      #     be used in some situations. On platforms that support forking, this
      #     is the default. If you use this runner, you should ensure that all
      #     of your one-time setup logic goes in a `before(:suite)` hook instead
      #     of getting run at the top-level of a file loaded by `--require`.
      #
      # @note This option will only be used by `--bisect` if you set it in a file
      #   loaded via `--require`.
      #
      # @return [Symbol]
      attr_reader :bisect_runner
      def bisect_runner=(value)
        if @bisect_runner_class && value != @bisect_runner
          raise "`config.bisect_runner = #{value.inspect}` can no longer take " \
            "effect as the #{@bisect_runner.inspect} bisect runnner is already " \
            "in use. This config setting must be set in a file loaded by a " \
            "`--require` option (passed at the CLI or in a `.rspec` file) for " \
            "it to have any effect."
        end

        @bisect_runner = value
      end

      # @private
      # @deprecated Use {#color_mode} = :on, instead of {#color} with {#tty}
      add_setting :tty
      # @private
      attr_writer :files_to_run
      # @private
      attr_accessor :filter_manager, :world
      # @private
      attr_accessor :static_config_filter_manager
      # @private
      attr_reader :backtrace_formatter, :ordering_manager, :loaded_spec_files

      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength

      # Build an object to store runtime configuration options and set defaults
      def initialize
        # rubocop:disable Style/GlobalVars
        @start_time = $_rspec_core_load_started_at || ::RSpec::Core::Time.now
        # rubocop:enable Style/GlobalVars
        @expectation_frameworks = []
        @include_modules = FilterableItemRepository::QueryOptimized.new(:any?)
        @extend_modules  = FilterableItemRepository::QueryOptimized.new(:any?)
        @prepend_modules = FilterableItemRepository::QueryOptimized.new(:any?)

        @bisect_runner = RSpec::Support::RubyFeatures.fork_supported? ? :fork : :shell
        @bisect_runner_class = nil

        @before_suite_hooks = []
        @after_suite_hooks  = []

        @mock_framework = nil
        @files_or_directories_to_run = []
        @loaded_spec_files = Set.new
        @color = false
        @color_mode = :automatic
        @pattern = '**{,/*/**}/*_spec.rb'
        @exclude_pattern = ''
        @failure_exit_code = 1
        @fail_if_no_examples = false
        @spec_files_loaded = false

        @backtrace_formatter = BacktraceFormatter.new

        @default_path = 'spec'
        @project_source_dirs = %w[ spec lib app ]
        @deprecation_stream = $stderr
        @output_stream = $stdout
        @reporter = nil
        @reporter_buffer = nil
        @filter_manager = FilterManager.new
        @static_config_filter_manager = FilterManager.new
        @ordering_manager = Ordering::ConfigurationManager.new
        @preferred_options = {}
        @failure_color = :red
        @success_color = :green
        @pending_color = :yellow
        @default_color = :white
        @fixed_color = :blue
        @detail_color = :cyan
        @profile_examples = false
        @requires = []
        @libs = []
        @derived_metadata_blocks = FilterableItemRepository::QueryOptimized.new(:any?)
        @threadsafe = true
        @max_displayed_failure_line_count = 10
        @world = World::Null
        @shared_context_metadata_behavior = :trigger_inclusion

        define_built_in_hooks
      end
      # rubocop:enable Metrics/MethodLength, Metrics/AbcSize

      # @private
      #
      # Used to set higher priority option values from the command line.
      def force(hash)
        ordering_manager.force(hash)
        @preferred_options.merge!(hash)

        return unless hash.key?(:example_status_persistence_file_path)
        clear_values_derived_from_example_status_persistence_file_path
      end

      # @private
      def reset
        @spec_files_loaded = false
        reset_reporter
      end

      # @private
      def reset_reporter
        @reporter = nil
        @formatter_loader = nil
        @output_wrapper = nil
      end

      # @private
      def reset_filters
        self.filter_manager = FilterManager.new
        filter_manager.include_only(
          Metadata.deep_hash_dup(static_config_filter_manager.inclusions.rules)
        )
        filter_manager.exclude_only(
          Metadata.deep_hash_dup(static_config_filter_manager.exclusions.rules)
        )
      end

      # @overload add_setting(name)
      # @overload add_setting(name, opts)
      # @option opts [Symbol] :default
      #
      #   Set a default value for the generated getter and predicate methods:
      #
      #       add_setting(:foo, :default => "default value")
      #
      # @option opts [Symbol] :alias_with
      #
      #   Use `:alias_with` to alias the setter, getter, and predicate to
      #   another name, or names:
      #
      #       add_setting(:foo, :alias_with => :bar)
      #       add_setting(:foo, :alias_with => [:bar, :baz])
      #
      # Adds a custom setting to the RSpec.configuration object.
      #
      #     RSpec.configuration.add_setting :foo
      #
      # Used internally and by extension frameworks like rspec-rails, so they
      # can add config settings that are domain specific. For example:
      #
      #     RSpec.configure do |c|
      #       c.add_setting :use_transactional_fixtures,
      #         :default => true,
      #         :alias_with => :use_transactional_examples
      #     end
      #
      # `add_setting` creates three methods on the configuration object, a
      # setter, a getter, and a predicate:
      #
      #     RSpec.configuration.foo=(value)
      #     RSpec.configuration.foo
      #     RSpec.configuration.foo? # Returns true if foo returns anything but nil or false.
      def add_setting(name, opts={})
        default = opts.delete(:default)
        (class << self; self; end).class_exec do
          add_setting(name, opts)
        end
        __send__("#{name}=", default) if default
      end

      # Returns the configured mock framework adapter module.
      # @return [Symbol]
      def mock_framework
        if @mock_framework.nil?
          begin
            mock_with :rspec
          rescue LoadError
            mock_with :nothing
          end
        end
        @mock_framework
      end

      # Delegates to mock_framework=(framework).
      def mock_framework=(framework)
        mock_with framework
      end

      # Regexps used to exclude lines from backtraces.
      #
      # Excludes lines from ruby (and jruby) source, installed gems, anything
      # in any "bin" directory, and any of the RSpec libs (outside gem
      # installs) by default.
      #
      # You can modify the list via the getter, or replace it with the setter.
      #
      # To override this behaviour and display a full backtrace, use
      # `--backtrace` on the command line, in a `.rspec` file, or in the
      # `rspec_options` attribute of RSpec's rake task.
      # @return [Array<Regexp>]
      def backtrace_exclusion_patterns
        @backtrace_formatter.exclusion_patterns
      end

      # Set regular expressions used to exclude lines in backtrace.
      # @param patterns [Array<Regexp>] set backtrace_formatter exlusion_patterns
      def backtrace_exclusion_patterns=(patterns)
        @backtrace_formatter.exclusion_patterns = patterns
      end

      # Regexps used to include lines in backtraces.
      #
      # Defaults to [Regexp.new Dir.getwd].
      #
      # Lines that match an exclusion _and_ an inclusion pattern
      # will be included.
      #
      # You can modify the list via the getter, or replace it with the setter.
      # @return [Array<Regexp>]
      def backtrace_inclusion_patterns
        @backtrace_formatter.inclusion_patterns
      end

      # Set regular expressions used to include lines in backtrace.
      # @attr patterns [Array<Regexp>] set backtrace_formatter inclusion_patterns
      def backtrace_inclusion_patterns=(patterns)
        @backtrace_formatter.inclusion_patterns = patterns
      end

      # Adds {#backtrace_exclusion_patterns} that will filter lines from
      # the named gems from backtraces.
      #
      # @param gem_names [Array<String>] Names of the gems to filter
      #
      # @example
      #   RSpec.configure do |config|
      #     config.filter_gems_from_backtrace "rack", "rake"
      #   end
      #
      # @note The patterns this adds will match the named gems in their common
      #   locations (e.g. system gems, vendored with bundler, installed as a
      #   :git dependency with bundler, etc) but is not guaranteed to work for
      #   all possible gem locations. For example, if you have the gem source
      #   in a directory with a completely unrelated name, and use bundler's
      #   :path option, this will not filter it.
      def filter_gems_from_backtrace(*gem_names)
        gem_names.each do |name|
          @backtrace_formatter.filter_gem(name)
        end
      end

      # @private
      MOCKING_ADAPTERS = {
        :rspec    => :RSpec,
        :flexmock => :Flexmock,
        :rr       => :RR,
        :mocha    => :Mocha,
        :nothing  => :Null
      }

      # Sets the mock framework adapter module.
      #
      # `framework` can be a Symbol or a Module.
      #
      # Given any of `:rspec`, `:mocha`, `:flexmock`, or `:rr`, configures the
      # named framework.
      #
      # Given `:nothing`, configures no framework. Use this if you don't use
      # any mocking framework to save a little bit of overhead.
      #
      # Given a Module, includes that module in every example group. The module
      # should adhere to RSpec's mock framework adapter API:
      #
      #     setup_mocks_for_rspec
      #       - called before each example
      #
      #     verify_mocks_for_rspec
      #       - called after each example if the example hasn't yet failed.
      #         Framework should raise an exception when expectations fail
      #
      #     teardown_mocks_for_rspec
      #       - called after verify_mocks_for_rspec (even if there are errors)
      #
      # If the module responds to `configuration` and `mock_with` receives a
      # block, it will yield the configuration object to the block e.g.
      #
      #     config.mock_with OtherMockFrameworkAdapter do |mod_config|
      #       mod_config.custom_setting = true
      #     end
      def mock_with(framework)
        framework_module =
          if framework.is_a?(Module)
            framework
          else
            const_name = MOCKING_ADAPTERS.fetch(framework) do
              raise ArgumentError,
                    "Unknown mocking framework: #{framework.inspect}. " \
                    "Pass a module or one of #{MOCKING_ADAPTERS.keys.inspect}"
            end

            RSpec::Support.require_rspec_core "mocking_adapters/#{const_name.to_s.downcase}"
            RSpec::Core::MockingAdapters.const_get(const_name)
          end

        new_name, old_name = [framework_module, @mock_framework].map do |mod|
          mod.respond_to?(:framework_name) ? mod.framework_name : :unnamed
        end

        unless new_name == old_name
          assert_no_example_groups_defined(:mock_framework)
        end

        if block_given?
          raise "#{framework_module} must respond to `configuration` so that " \
                "mock_with can yield it." unless framework_module.respond_to?(:configuration)
          yield framework_module.configuration
        end

        @mock_framework = framework_module
      end

      # Returns the configured expectation framework adapter module(s)
      def expectation_frameworks
        if @expectation_frameworks.empty?
          begin
            expect_with :rspec
          rescue LoadError
            expect_with Module.new
          end
        end
        @expectation_frameworks
      end

      # Delegates to expect_with(framework).
      def expectation_framework=(framework)
        expect_with(framework)
      end

      # Sets the expectation framework module(s) to be included in each example
      # group.
      #
      # `frameworks` can be `:rspec`, `:test_unit`, `:minitest`, a custom
      # module, or any combination thereof:
      #
      #     config.expect_with :rspec
      #     config.expect_with :test_unit
      #     config.expect_with :minitest
      #     config.expect_with :rspec, :minitest
      #     config.expect_with OtherExpectationFramework
      #
      # RSpec will translate `:rspec`, `:minitest`, and `:test_unit` into the
      # appropriate modules.
      #
      # ## Configuration
      #
      # If the module responds to `configuration`, `expect_with` will
      # yield the `configuration` object if given a block:
      #
      #     config.expect_with OtherExpectationFramework do |custom_config|
      #       custom_config.custom_setting = true
      #     end
      def expect_with(*frameworks)
        modules = frameworks.map do |framework|
          case framework
          when Module
            framework
          when :rspec
            require 'rspec/expectations'

            # Tag this exception class so our exception formatting logic knows
            # that it satisfies the `MultipleExceptionError` interface.
            ::RSpec::Expectations::MultipleExpectationsNotMetError.__send__(
              :include, MultipleExceptionError::InterfaceTag
            )

            ::RSpec::Matchers
          when :test_unit
            require 'rspec/core/test_unit_assertions_adapter'
            ::RSpec::Core::TestUnitAssertionsAdapter
          when :minitest
            require 'rspec/core/minitest_assertions_adapter'
            ::RSpec::Core::MinitestAssertionsAdapter
          else
            raise ArgumentError, "#{framework.inspect} is not supported"
          end
        end

        if (modules - @expectation_frameworks).any?
          assert_no_example_groups_defined(:expect_with)
        end

        if block_given?
          raise "expect_with only accepts a block with a single argument. " \
                "Call expect_with #{modules.length} times, " \
                "once with each argument, instead." if modules.length > 1
          raise "#{modules.first} must respond to `configuration` so that " \
                "expect_with can yield it." unless modules.first.respond_to?(:configuration)
          yield modules.first.configuration
        end

        @expectation_frameworks.push(*modules)
      end

      # Check if full backtrace is enabled.
      # @return [Boolean] is full backtrace enabled
      def full_backtrace?
        @backtrace_formatter.full_backtrace?
      end

      # Toggle full backtrace.
      # @attr true_or_false [Boolean] toggle full backtrace display
      def full_backtrace=(true_or_false)
        @backtrace_formatter.full_backtrace = true_or_false
      end

      # Enables color output if the output is a TTY.  As of RSpec 3.6, this is
      # the default behavior and this option is retained only for backwards
      # compatibility.
      #
      # @deprecated No longer recommended because of complex behavior. Instead,
      #   rely on the fact that TTYs will display color by default, or set
      #   {#color_mode} to :on to display color on a non-TTY output.
      # @see color_mode
      # @see color_enabled?
      # @return [Boolean]
      def color
        value_for(:color) { @color }
      end

      # The mode for determining whether to display output in color. One of:
      #
      # - :automatic - the output will be in color if the output is a TTY (the
      #   default)
      # - :on - the output will be in color, whether or not the output is a TTY
      # - :off - the output will not be in color
      #
      # @see color_enabled?
      # @return [Boolean]
      def color_mode
        value_for(:color_mode) { @color_mode }
      end

      # Check if color is enabled for a particular output.
      # @param output [IO] an output stream to use, defaults to the current
      #        `output_stream`
      # @return [Boolean]
      def color_enabled?(output=output_stream)
        case color_mode
        when :on then true
        when :off then false
        else # automatic
          output_to_tty?(output) || (color && tty?)
        end
      end

      # Set the color mode.
      attr_writer :color_mode

      # Toggle output color.
      #
      # @deprecated No longer recommended because of complex behavior. Instead,
      #   rely on the fact that TTYs will display color by default, or set
      #   {:color_mode} to :on to display color on a non-TTY output.
      attr_writer :color

      # @private
      def libs=(libs)
        libs.map do |lib|
          @libs.unshift lib
          $LOAD_PATH.unshift lib
        end
      end

      # Run examples matching on `description` in all files to run.
      # @param description [String, Regexp] the pattern to filter on
      def full_description=(description)
        filter_run :full_description => Regexp.union(*Array(description).map { |d| Regexp.new(d) })
      end

      # @return [Array] full description filter
      def full_description
        filter.fetch :full_description, nil
      end

      # @overload add_formatter(formatter)
      # @overload add_formatter(formatter, output)
      #
      # @param formatter [Class, String, Object] formatter to use. Can be any of the
      #   string values supported from the CLI (`p`/`progress`,
      #   `d`/`doc`/`documentation`, `h`/`html`, or `j`/`json`), any
      #   class that implements the formatter protocol and has registered
      #   itself with RSpec as a formatter, or a formatter instance.
      # @param output [String, IO] where the formatter will write its output.
      #   Can be an IO object or a string path to a file. If not provided,
      #   the configured `output_stream` (`$stdout`, by default) will be used.
      #
      # Adds a formatter to the set RSpec will use for this run.
      #
      # @see RSpec::Core::Formatters::Protocol
      def add_formatter(formatter, output=output_wrapper)
        formatter_loader.add(formatter, output)
      end
      alias_method :formatter=, :add_formatter

      # The formatter that will be used if no formatter has been set.
      # Defaults to 'progress'.
      def default_formatter
        formatter_loader.default_formatter
      end

      # Sets a fallback formatter to use if none other has been set.
      #
      # @example
      #
      #   RSpec.configure do |rspec|
      #     rspec.default_formatter = 'doc'
      #   end
      def default_formatter=(value)
        formatter_loader.default_formatter = value
      end

      # Returns a duplicate of the formatters currently loaded in
      # the `FormatterLoader` for introspection.
      #
      # Note as this is a duplicate, any mutations will be disregarded.
      #
      # @return [Array] the formatters currently loaded
      def formatters
        formatter_loader.formatters.dup
      end

      # @private
      def formatter_loader
        @formatter_loader ||= Formatters::Loader.new(Reporter.new(self))
      end

      # @private
      #
      # This buffer is used to capture all messages sent to the reporter during
      # reporter initialization. It can then replay those messages after the
      # formatter is correctly initialized. Otherwise, deprecation warnings
      # during formatter initialization can cause an infinite loop.
      class DeprecationReporterBuffer
        def initialize
          @calls = []
        end

        def deprecation(*args)
          @calls << args
        end

        def play_onto(reporter)
          @calls.each do |args|
            reporter.deprecation(*args)
          end
        end
      end

      # @return [RSpec::Core::Reporter] the currently configured reporter
      def reporter
        # @reporter_buffer should only ever be set in this method to cover
        # initialization of @reporter.
        @reporter_buffer || @reporter ||=
          begin
            @reporter_buffer = DeprecationReporterBuffer.new
            formatter_loader.prepare_default output_wrapper, deprecation_stream
            @reporter_buffer.play_onto(formatter_loader.reporter)
            @reporter_buffer = nil
            formatter_loader.reporter
          end
      end

      # @api private
      #
      # Defaults `profile_examples` to 10 examples when `@profile_examples` is
      # `true`.
      def profile_examples
        profile = value_for(:profile_examples) { @profile_examples }
        if profile && !profile.is_a?(Integer)
          10
        else
          profile
        end
      end

      # @private
      def files_or_directories_to_run=(*files)
        files = files.flatten

        if (command == 'rspec' || Runner.running_in_drb?) && default_path && files.empty?
          files << default_path
        end

        @files_or_directories_to_run = files
        @files_to_run = nil
      end

      # The spec files RSpec will run.
      # @return [Array] specified files about to run
      def files_to_run
        @files_to_run ||= get_files_to_run(@files_or_directories_to_run)
      end

      # @private
      def last_run_statuses
        @last_run_statuses ||= Hash.new(UNKNOWN_STATUS).tap do |statuses|
          if (path = example_status_persistence_file_path)
            begin
              ExampleStatusPersister.load_from(path).inject(statuses) do |hash, example|
                status = example[:status]
                status = UNKNOWN_STATUS unless VALID_STATUSES.include?(status)
                hash[example.fetch(:example_id)] = status
                hash
              end
            rescue SystemCallError => e
              RSpec.warning "Could not read from #{path.inspect} (configured as " \
                            "`config.example_status_persistence_file_path`) due " \
                            "to a system error: #{e.inspect}. Please check that " \
                            "the config option is set to an accessible, valid " \
                            "file path", :call_site => nil
            end
          end
        end
      end

      # @private
      UNKNOWN_STATUS = "unknown".freeze

      # @private
      FAILED_STATUS = "failed".freeze

      # @private
      PASSED_STATUS = "passed".freeze

      # @private
      PENDING_STATUS = "pending".freeze

      # @private
      VALID_STATUSES = [UNKNOWN_STATUS, FAILED_STATUS, PASSED_STATUS, PENDING_STATUS]

      # @private
      def spec_files_with_failures
        @spec_files_with_failures ||= last_run_statuses.inject(Set.new) do |files, (id, status)|
          files << Example.parse_id(id).first if status == FAILED_STATUS
          files
        end.to_a
      end

      # Creates a method that delegates to `example` including the submitted
      # `args`. Used internally to add variants of `example` like `pending`:
      # @param name [String] example name alias
      # @param args [Array<Symbol>, Hash] metadata for the generated example
      #
      # @note The specific example alias below (`pending`) is already
      #   defined for you.
      # @note Use with caution. This extends the language used in your
      #   specs, but does not add any additional documentation. We use this
      #   in RSpec to define methods like `focus` and `xit`, but we also add
      #   docs for those methods.
      #
      # @example
      #   RSpec.configure do |config|
      #     config.alias_example_to :pending, :pending => true
      #   end
      #
      #   # This lets you do this:
      #
      #   describe Thing do
      #     pending "does something" do
      #       thing = Thing.new
      #     end
      #   end
      #
      #   # ... which is the equivalent of
      #
      #   describe Thing do
      #     it "does something", :pending => true do
      #       thing = Thing.new
      #     end
      #   end
      def alias_example_to(name, *args)
        extra_options = Metadata.build_hash_from(args)
        RSpec::Core::ExampleGroup.define_example_method(name, extra_options)
      end

      # Creates a method that defines an example group with the provided
      # metadata. Can be used to define example group/metadata shortcuts.
      #
      # @example
      #   RSpec.configure do |config|
      #     config.alias_example_group_to :describe_model, :type => :model
      #   end
      #
      #   shared_context_for "model tests", :type => :model do
      #     # define common model test helper methods, `let` declarations, etc
      #   end
      #
      #   # This lets you do this:
      #
      #   RSpec.describe_model User do
      #   end
      #
      #   # ... which is the equivalent of
      #
      #   RSpec.describe User, :type => :model do
      #   end
      #
      # @note The defined aliased will also be added to the top level
      #       (e.g. `main` and from within modules) if
      #       `expose_dsl_globally` is set to true.
      # @see #alias_example_to
      # @see #expose_dsl_globally=
      def alias_example_group_to(new_name, *args)
        extra_options = Metadata.build_hash_from(args)
        RSpec::Core::ExampleGroup.define_example_group_method(new_name, extra_options)
      end

      # Define an alias for it_should_behave_like that allows different
      # language (like "it_has_behavior" or "it_behaves_like") to be
      # employed when including shared examples.
      #
      # @example
      #   RSpec.configure do |config|
      #     config.alias_it_behaves_like_to(:it_has_behavior, 'has behavior:')
      #   end
      #
      #   # allows the user to include a shared example group like:
      #
      #   describe Entity do
      #     it_has_behavior 'sortability' do
      #       let(:sortable) { Entity.new }
      #     end
      #   end
      #
      #   # which is reported in the output as:
      #   # Entity
      #   #   has behavior: sortability
      #   #     ...sortability examples here
      #
      # @note Use with caution. This extends the language used in your
      #   specs, but does not add any additional documentation. We use this
      #   in RSpec to define `it_should_behave_like` (for backward
      #   compatibility), but we also add docs for that method.
      def alias_it_behaves_like_to(new_name, report_label='')
        RSpec::Core::ExampleGroup.define_nested_shared_group_method(new_name, report_label)
      end
      alias_method :alias_it_should_behave_like_to, :alias_it_behaves_like_to

      # Adds key/value pairs to the `inclusion_filter`. If `args`
      # includes any symbols that are not part of the hash, each symbol
      # is treated as a key in the hash with the value `true`.
      #
      # ### Note
      #
      # Filters set using this method can be overridden from the command line
      # or config files (e.g. `.rspec`).
      #
      # @example
      #     # Given this declaration.
      #     describe "something", :foo => 'bar' do
      #       # ...
      #     end
      #
      #     # Any of the following will include that group.
      #     config.filter_run_including :foo => 'bar'
      #     config.filter_run_including :foo => /^ba/
      #     config.filter_run_including :foo => lambda {|v| v == 'bar'}
      #     config.filter_run_including :foo => lambda {|v,m| m[:foo] == 'bar'}
      #
      #     # Given a proc with an arity of 1, the lambda is passed the value
      #     # related to the key, e.g.
      #     config.filter_run_including :foo => lambda {|v| v == 'bar'}
      #
      #     # Given a proc with an arity of 2, the lambda is passed the value
      #     # related to the key, and the metadata itself e.g.
      #     config.filter_run_including :foo => lambda {|v,m| m[:foo] == 'bar'}
      #
      #     filter_run_including :foo # same as filter_run_including :foo => true
      def filter_run_including(*args)
        meta = Metadata.build_hash_from(args, :warn_about_example_group_filtering)
        filter_manager.include_with_low_priority meta
        static_config_filter_manager.include_with_low_priority Metadata.deep_hash_dup(meta)
      end
      alias_method :filter_run, :filter_run_including

      # Applies the provided filter only if any of examples match, in constrast
      # to {#filter_run}, which always applies even if no examples match, in
      # which case no examples will be run. This allows you to leave configured
      # filters in place that are intended only for temporary use. The most common
      # example is focus filtering: `config.filter_run_when_matching :focus`.
      # With that configured, you can temporarily focus an example or group
      # by tagging it with `:focus` metadata, or prefixing it with an `f`
      # (as in `fdescribe`, `fcontext` and `fit`) since those are aliases for
      # `describe`/`context`/`it` with `:focus` metadata.
      def filter_run_when_matching(*args)
        when_first_matching_example_defined(*args) do
          filter_run(*args)
        end
      end

      # Clears and reassigns the `inclusion_filter`. Set to `nil` if you don't
      # want any inclusion filter at all.
      #
      # ### Warning
      #
      # This overrides any inclusion filters/tags set on the command line or in
      # configuration files.
      def inclusion_filter=(filter)
        meta = Metadata.build_hash_from([filter], :warn_about_example_group_filtering)
        filter_manager.include_only meta
      end

      alias_method :filter=, :inclusion_filter=

      # Returns the `inclusion_filter`. If none has been set, returns an empty
      # hash.
      def inclusion_filter
        filter_manager.inclusions
      end

      alias_method :filter, :inclusion_filter

      # Adds key/value pairs to the `exclusion_filter`. If `args`
      # includes any symbols that are not part of the hash, each symbol
      # is treated as a key in the hash with the value `true`.
      #
      # ### Note
      #
      # Filters set using this method can be overridden from the command line
      # or config files (e.g. `.rspec`).
      #
      # @example
      #     # Given this declaration.
      #     describe "something", :foo => 'bar' do
      #       # ...
      #     end
      #
      #     # Any of the following will exclude that group.
      #     config.filter_run_excluding :foo => 'bar'
      #     config.filter_run_excluding :foo => /^ba/
      #     config.filter_run_excluding :foo => lambda {|v| v == 'bar'}
      #     config.filter_run_excluding :foo => lambda {|v,m| m[:foo] == 'bar'}
      #
      #     # Given a proc with an arity of 1, the lambda is passed the value
      #     # related to the key, e.g.
      #     config.filter_run_excluding :foo => lambda {|v| v == 'bar'}
      #
      #     # Given a proc with an arity of 2, the lambda is passed the value
      #     # related to the key, and the metadata itself e.g.
      #     config.filter_run_excluding :foo => lambda {|v,m| m[:foo] == 'bar'}
      #
      #     filter_run_excluding :foo # same as filter_run_excluding :foo => true
      def filter_run_excluding(*args)
        meta = Metadata.build_hash_from(args, :warn_about_example_group_filtering)
        filter_manager.exclude_with_low_priority meta
        static_config_filter_manager.exclude_with_low_priority Metadata.deep_hash_dup(meta)
      end

      # Clears and reassigns the `exclusion_filter`. Set to `nil` if you don't
      # want any exclusion filter at all.
      #
      # ### Warning
      #
      # This overrides any exclusion filters/tags set on the command line or in
      # configuration files.
      def exclusion_filter=(filter)
        meta = Metadata.build_hash_from([filter], :warn_about_example_group_filtering)
        filter_manager.exclude_only meta
      end

      # Returns the `exclusion_filter`. If none has been set, returns an empty
      # hash.
      def exclusion_filter
        filter_manager.exclusions
      end

      # Tells RSpec to include `mod` in example groups. Methods defined in
      # `mod` are exposed to examples (not example groups). Use `filters` to
      # constrain the groups or examples in which to include the module.
      #
      # @example
      #
      #     module AuthenticationHelpers
      #       def login_as(user)
      #         # ...
      #       end
      #     end
      #
      #     module UserHelpers
      #       def users(username)
      #         # ...
      #       end
      #     end
      #
      #     RSpec.configure do |config|
      #       config.include(UserHelpers) # included in all groups
      #       config.include(AuthenticationHelpers, :type => :request)
      #     end
      #
      #     describe "edit profile", :type => :request do
      #       it "can be viewed by owning user" do
      #         login_as users(:jdoe)
      #         get "/profiles/jdoe"
      #         assert_select ".username", :text => 'jdoe'
      #       end
      #     end
      #
      # @note Filtered module inclusions can also be applied to
      #   individual examples that have matching metadata. Just like
      #   Ruby's object model is that every object has a singleton class
      #   which has only a single instance, RSpec's model is that every
      #   example has a singleton example group containing just the one
      #   example.
      #
      # @see #include_context
      # @see #extend
      # @see #prepend
      def include(mod, *filters)
        define_mixed_in_module(mod, filters, @include_modules, :include) do |group|
          safe_include(mod, group)
        end
      end

      # Tells RSpec to include the named shared example group in example groups.
      # Use `filters` to constrain the groups or examples in which to include
      # the example group.
      #
      # @example
      #
      #     RSpec.shared_context "example users" do
      #       let(:admin_user) { create_user(:admin) }
      #       let(:guest_user) { create_user(:guest) }
      #     end
      #
      #     RSpec.configure do |config|
      #       config.include_context "example users", :type => :request
      #     end
      #
      #     RSpec.describe "The admin page", :type => :request do
      #       it "can be viewed by admins" do
      #         login_with admin_user
      #         get "/admin"
      #         expect(response).to be_ok
      #       end
      #
      #       it "cannot be viewed by guests" do
      #         login_with guest_user
      #         get "/admin"
      #         expect(response).to be_forbidden
      #       end
      #     end
      #
      # @note Filtered context inclusions can also be applied to
      #   individual examples that have matching metadata. Just like
      #   Ruby's object model is that every object has a singleton class
      #   which has only a single instance, RSpec's model is that every
      #   example has a singleton example group containing just the one
      #   example.
      #
      # @see #include
      def include_context(shared_group_name, *filters)
        shared_module = world.shared_example_group_registry.find([:main], shared_group_name)
        include shared_module, *filters
      end

      # Tells RSpec to extend example groups with `mod`. Methods defined in
      # `mod` are exposed to example groups (not examples). Use `filters` to
      # constrain the groups to extend.
      #
      # Similar to `include`, but behavior is added to example groups, which
      # are classes, rather than the examples, which are instances of those
      # classes.
      #
      # @example
      #
      #     module UiHelpers
      #       def run_in_browser
      #         # ...
      #       end
      #     end
      #
      #     RSpec.configure do |config|
      #       config.extend(UiHelpers, :type => :request)
      #     end
      #
      #     describe "edit profile", :type => :request do
      #       run_in_browser
      #
      #       it "does stuff in the client" do
      #         # ...
      #       end
      #     end
      #
      # @see #include
      # @see #prepend
      def extend(mod, *filters)
        define_mixed_in_module(mod, filters, @extend_modules, :extend) do |group|
          safe_extend(mod, group)
        end
      end

      if RSpec::Support::RubyFeatures.module_prepends_supported?
        # Tells RSpec to prepend example groups with `mod`. Methods defined in
        # `mod` are exposed to examples (not example groups). Use `filters` to
        # constrain the groups in which to prepend the module.
        #
        # Similar to `include`, but module is included before the example group's class
        # in the ancestor chain.
        #
        # @example
        #
        #     module OverrideMod
        #       def override_me
        #         "overridden"
        #       end
        #     end
        #
        #     RSpec.configure do |config|
        #       config.prepend(OverrideMod, :method => :prepend)
        #     end
        #
        #     describe "overriding example's class", :method => :prepend do
        #       it "finds the user" do
        #         self.class.class_eval do
        #           def override_me
        #           end
        #         end
        #         override_me # => "overridden"
        #         # ...
        #       end
        #     end
        #
        # @see #include
        # @see #extend
        def prepend(mod, *filters)
          define_mixed_in_module(mod, filters, @prepend_modules, :prepend) do |group|
            safe_prepend(mod, group)
          end
        end
      end

      # @private
      #
      # Used internally to extend a group with modules using `include`, `prepend` and/or
      # `extend`.
      def configure_group(group)
        group.hooks.register_globals(group, hooks)

        configure_group_with group, @include_modules, :safe_include
        configure_group_with group, @extend_modules,  :safe_extend
        configure_group_with group, @prepend_modules, :safe_prepend
      end

      # @private
      #
      # Used internally to extend the singleton class of a single example's
      # example group instance with modules using `include` and/or `extend`.
      def configure_example(example, example_hooks)
        example_hooks.register_global_singleton_context_hooks(example, hooks)
        singleton_group = example.example_group_instance.singleton_class

        # We replace the metadata so that SharedExampleGroupModule#included
        # has access to the example's metadata[:location].
        singleton_group.with_replaced_metadata(example.metadata) do
          modules = @include_modules.items_for(example.metadata)
          modules.each do |mod|
            safe_include(mod, example.example_group_instance.singleton_class)
          end

          MemoizedHelpers.define_helpers_on(singleton_group) unless modules.empty?
        end
      end

      # @private
      def requires=(paths)
        directories = ['lib', default_path].select { |p| File.directory? p }
        RSpec::Core::RubyProject.add_to_load_path(*directories)
        paths.each { |path| load_file_handling_errors(:require, path) }
        @requires += paths
      end

      # @private
      def in_project_source_dir_regex
        regexes = project_source_dirs.map do |dir|
          /\A#{Regexp.escape(File.expand_path(dir))}\//
        end

        Regexp.union(regexes)
      end

      # @private
      def configure_mock_framework
        RSpec::Core::ExampleGroup.__send__(:include, mock_framework)
        conditionally_disable_mocks_monkey_patching
      end

      # @private
      def configure_expectation_framework
        expectation_frameworks.each do |framework|
          RSpec::Core::ExampleGroup.__send__(:include, framework)
        end
        conditionally_disable_expectations_monkey_patching
      end

      # @private
      def load_spec_files
        # Note which spec files world is already aware of.
        # This is generally only needed for when the user runs
        # `ruby path/to/spec.rb` (and loads `rspec/autorun`) --
        # in that case, the spec file was loaded by `ruby` and
        # isn't loaded by us here so we only know about it because
        # of an example group being registered in it.
        world.registered_example_group_files.each do |f|
          loaded_spec_files << f # the registered files are already expended absolute paths
        end

        files_to_run.uniq.each do |f|
          file = File.expand_path(f)
          load_file_handling_errors(:load, file)
          loaded_spec_files << file
        end

        @spec_files_loaded = true
      end

      # @private
      DEFAULT_FORMATTER = lambda { |string| string }

      # Formats the docstring output using the block provided.
      #
      # @example
      #   # This will strip the descriptions of both examples and example
      #   # groups.
      #   RSpec.configure do |config|
      #     config.format_docstrings { |s| s.strip }
      #   end
      def format_docstrings(&block)
        @format_docstrings_block = block_given? ? block : DEFAULT_FORMATTER
      end

      # @private
      def format_docstrings_block
        @format_docstrings_block ||= DEFAULT_FORMATTER
      end

      # @private
      def self.delegate_to_ordering_manager(*methods)
        methods.each do |method|
          define_method method do |*args, &block|
            ordering_manager.__send__(method, *args, &block)
          end
        end
      end

      # @!method seed=(value)
      #
      # Sets the seed value and sets the default global ordering to random.
      delegate_to_ordering_manager :seed=

      # @!method seed
      # Seed for random ordering (default: generated randomly each run).
      #
      # When you run specs with `--order random`, RSpec generates a random seed
      # for the randomization and prints it to the `output_stream` (assuming
      # you're using RSpec's built-in formatters). If you discover an ordering
      # dependency (i.e. examples fail intermittently depending on order), set
      # this (on Configuration or on the command line with `--seed`) to run
      # using the same seed while you debug the issue.
      #
      # We recommend, actually, that you use the command line approach so you
      # don't accidentally leave the seed encoded.
      delegate_to_ordering_manager :seed

      # @!method order=(value)
      #
      # Sets the default global ordering strategy. By default this can be one
      # of `:defined`, `:random`, but is customizable through the
      # `register_ordering` API. If order is set to `'rand:<seed>'`,
      # the seed will also be set.
      #
      # @see #register_ordering
      delegate_to_ordering_manager :order=

      # @!method register_ordering(name)
      #
      # Registers a named ordering strategy that can later be
      # used to order an example group's subgroups by adding
      # `:order => <name>` metadata to the example group.
      #
      # @param name [Symbol] The name of the ordering.
      # @yield Block that will order the given examples or example groups
      # @yieldparam list [Array<RSpec::Core::Example>,
      #   Array<RSpec::Core::ExampleGroup>] The examples or groups to order
      # @yieldreturn [Array<RSpec::Core::Example>,
      #   Array<RSpec::Core::ExampleGroup>] The re-ordered examples or groups
      #
      # @example
      #   RSpec.configure do |rspec|
      #     rspec.register_ordering :reverse do |list|
      #       list.reverse
      #     end
      #   end
      #
      #   RSpec.describe 'MyClass', :order => :reverse do
      #     # ...
      #   end
      #
      # @note Pass the symbol `:global` to set the ordering strategy that
      #   will be used to order the top-level example groups and any example
      #   groups that do not have declared `:order` metadata.
      #
      # @example
      #   RSpec.configure do |rspec|
      #     rspec.register_ordering :global do |examples|
      #       acceptance, other = examples.partition do |example|
      #         example.metadata[:type] == :acceptance
      #       end
      #       other + acceptance
      #     end
      #   end
      #
      #   RSpec.describe 'MyClass', :type => :acceptance do
      #     # will run last
      #   end
      #
      #   RSpec.describe 'MyClass' do
      #     # will run first
      #   end
      #
      delegate_to_ordering_manager :register_ordering

      # @private
      delegate_to_ordering_manager :seed_used?, :ordering_registry

      # Set Ruby warnings on or off.
      def warnings=(value)
        $VERBOSE = !!value
      end

      # @return [Boolean] Whether or not ruby warnings are enabled.
      def warnings?
        $VERBOSE
      end

      # @private
      RAISE_ERROR_WARNING_NOTIFIER = lambda { |message| raise message }

      # Turns warnings into errors. This can be useful when
      # you want RSpec to run in a 'strict' no warning situation.
      #
      # @example
      #
      #   RSpec.configure do |rspec|
      #     rspec.raise_on_warning = true
      #   end
      def raise_on_warning=(value)
        if value
          RSpec::Support.warning_notifier = RAISE_ERROR_WARNING_NOTIFIER
        else
          RSpec::Support.warning_notifier = RSpec::Support::DEFAULT_WARNING_NOTIFIER
        end
      end

      # Exposes the current running example via the named
      # helper method. RSpec 2.x exposed this via `example`,
      # but in RSpec 3.0, the example is instead exposed via
      # an arg yielded to `it`, `before`, `let`, etc. However,
      # some extension gems (such as Capybara) depend on the
      # RSpec 2.x's `example` method, so this config option
      # can be used to maintain compatibility.
      #
      # @param method_name [Symbol] the name of the helper method
      #
      # @example
      #
      #   RSpec.configure do |rspec|
      #     rspec.expose_current_running_example_as :example
      #   end
      #
      #   describe MyClass do
      #     before do
      #       # `example` can be used here because of the above config.
      #       do_something if example.metadata[:type] == "foo"
      #     end
      #   end
      def expose_current_running_example_as(method_name)
        ExposeCurrentExample.module_exec do
          extend RSpec::SharedContext
          let(method_name) { |ex| ex }
        end

        include ExposeCurrentExample
      end

      # @private
      module ExposeCurrentExample; end

      # Turns deprecation warnings into errors, in order to surface
      # the full backtrace of the call site. This can be useful when
      # you need more context to address a deprecation than the
      # single-line call site normally provided.
      #
      # @example
      #
      #   RSpec.configure do |rspec|
      #     rspec.raise_errors_for_deprecations!
      #   end
      def raise_errors_for_deprecations!
        self.deprecation_stream = Formatters::DeprecationFormatter::RaiseErrorStream.new
      end

      # Enables zero monkey patching mode for RSpec. It removes monkey
      # patching of the top-level DSL methods (`describe`,
      # `shared_examples_for`, etc) onto `main` and `Module`, instead
      # requiring you to prefix these methods with `RSpec.`. It enables
      # expect-only syntax for rspec-mocks and rspec-expectations. It
      # simply disables monkey patching on whatever pieces of RSpec
      # the user is using.
      #
      # @note It configures rspec-mocks and rspec-expectations only
      #   if the user is using those (either explicitly or implicitly
      #   by not setting `mock_with` or `expect_with` to anything else).
      #
      # @note If the user uses this options with `mock_with :mocha`
      #   (or similiar) they will still have monkey patching active
      #   in their test environment from mocha.
      #
      # @example
      #
      #   # It disables all monkey patching.
      #   RSpec.configure do |config|
      #     config.disable_monkey_patching!
      #   end
      #
      #   # Is an equivalent to
      #   RSpec.configure do |config|
      #     config.expose_dsl_globally = false
      #
      #     config.mock_with :rspec do |mocks|
      #       mocks.syntax = :expect
      #       mocks.patch_marshal_to_support_partial_doubles = false
      #     end
      #
      #     config.expect_with :rspec do |expectations|
      #       expectations.syntax = :expect
      #     end
      #   end
      def disable_monkey_patching!
        self.expose_dsl_globally = false
        self.disable_monkey_patching = true
        conditionally_disable_mocks_monkey_patching
        conditionally_disable_expectations_monkey_patching
      end

      # @private
      attr_accessor :disable_monkey_patching

      # Defines a callback that can assign derived metadata values.
      #
      # @param filters [Array<Symbol>, Hash] metadata filters that determine
      #   which example or group metadata hashes the callback will be triggered
      #   for. If none are given, the callback will be run against the metadata
      #   hashes of all groups and examples.
      # @yieldparam metadata [Hash] original metadata hash from an example or
      #   group. Mutate this in your block as needed.
      #
      # @example
      #   RSpec.configure do |config|
      #     # Tag all groups and examples in the spec/unit directory with
      #     # :type => :unit
      #     config.define_derived_metadata(:file_path => %r{/spec/unit/}) do |metadata|
      #       metadata[:type] = :unit
      #     end
      #   end
      def define_derived_metadata(*filters, &block)
        meta = Metadata.build_hash_from(filters, :warn_about_example_group_filtering)
        @derived_metadata_blocks.append(block, meta)
      end

      # Defines a callback that runs after the first example with matching
      # metadata is defined. If no examples are defined with matching metadata,
      # it will not get called at all.
      #
      # This can be used to ensure some setup is performed (such as bootstrapping
      # a DB or loading a specific file that adds significantly to the boot time)
      # if needed (as indicated by the presence of an example with matching metadata)
      # but avoided otherwise.
      #
      # @example
      #   RSpec.configure do |config|
      #     config.when_first_matching_example_defined(:db) do
      #       # Load a support file that does some heavyweight setup,
      #       # including bootstrapping the DB, but only if we have loaded
      #       # any examples tagged with `:db`.
      #       require 'support/db'
      #     end
      #   end
      def when_first_matching_example_defined(*filters)
        specified_meta = Metadata.build_hash_from(filters, :warn_about_example_group_filtering)

        callback = lambda do |example_or_group_meta|
          # Example groups do not have `:example_group` metadata
          # (instead they have `:parent_example_group` metadata).
          return unless example_or_group_meta.key?(:example_group)

          # Ensure the callback only fires once.
          @derived_metadata_blocks.delete(callback, specified_meta)

          yield
        end

        @derived_metadata_blocks.append(callback, specified_meta)
      end

      # @private
      def apply_derived_metadata_to(metadata)
        @derived_metadata_blocks.items_for(metadata).each do |block|
          block.call(metadata)
        end
      end

      # Defines a `before` hook. See {Hooks#before} for full docs.
      #
      # This method differs from {Hooks#before} in only one way: it supports
      # the `:suite` scope. Hooks with the `:suite` scope will be run once before
      # the first example of the entire suite is executed.
      #
      # @see #prepend_before
      # @see #after
      # @see #append_after
      def before(scope=nil, *meta, &block)
        handle_suite_hook(scope, meta) do
          @before_suite_hooks << Hooks::BeforeHook.new(block, {})
        end || begin
          # defeat Ruby 2.5 lazy proc allocation to ensure
          # the methods below are passed the same proc instances
          # so `Hook` equality is preserved. For more info, see:
          # https://bugs.ruby-lang.org/issues/14045#note-5
          block.__id__

          add_hook_to_existing_matching_groups(meta, scope) { |g| g.before(scope, *meta, &block) }
          super(scope, *meta, &block)
        end
      end
      alias_method :append_before, :before

      # Adds `block` to the start of the list of `before` blocks in the same
      # scope (`:example`, `:context`, or `:suite`), in contrast to {#before},
      # which adds the hook to the end of the list.
      #
      # See {Hooks#before} for full `before` hook docs.
      #
      # This method differs from {Hooks#prepend_before} in only one way: it supports
      # the `:suite` scope. Hooks with the `:suite` scope will be run once before
      # the first example of the entire suite is executed.
      #
      # @see #before
      # @see #after
      # @see #append_after
      def prepend_before(scope=nil, *meta, &block)
        handle_suite_hook(scope, meta) do
          @before_suite_hooks.unshift Hooks::BeforeHook.new(block, {})
        end || begin
          # defeat Ruby 2.5 lazy proc allocation to ensure
          # the methods below are passed the same proc instances
          # so `Hook` equality is preserved. For more info, see:
          # https://bugs.ruby-lang.org/issues/14045#note-5
          block.__id__

          add_hook_to_existing_matching_groups(meta, scope) { |g| g.prepend_before(scope, *meta, &block) }
          super(scope, *meta, &block)
        end
      end

      # Defines a `after` hook. See {Hooks#after} for full docs.
      #
      # This method differs from {Hooks#after} in only one way: it supports
      # the `:suite` scope. Hooks with the `:suite` scope will be run once after
      # the last example of the entire suite is executed.
      #
      # @see #append_after
      # @see #before
      # @see #prepend_before
      def after(scope=nil, *meta, &block)
        handle_suite_hook(scope, meta) do
          @after_suite_hooks.unshift Hooks::AfterHook.new(block, {})
        end || begin
          # defeat Ruby 2.5 lazy proc allocation to ensure
          # the methods below are passed the same proc instances
          # so `Hook` equality is preserved. For more info, see:
          # https://bugs.ruby-lang.org/issues/14045#note-5
          block.__id__

          add_hook_to_existing_matching_groups(meta, scope) { |g| g.after(scope, *meta, &block) }
          super(scope, *meta, &block)
        end
      end
      alias_method :prepend_after, :after

      # Adds `block` to the end of the list of `after` blocks in the same
      # scope (`:example`, `:context`, or `:suite`), in contrast to {#after},
      # which adds the hook to the start of the list.
      #
      # See {Hooks#after} for full `after` hook docs.
      #
      # This method differs from {Hooks#append_after} in only one way: it supports
      # the `:suite` scope. Hooks with the `:suite` scope will be run once after
      # the last example of the entire suite is executed.
      #
      # @see #append_after
      # @see #before
      # @see #prepend_before
      def append_after(scope=nil, *meta, &block)
        handle_suite_hook(scope, meta) do
          @after_suite_hooks << Hooks::AfterHook.new(block, {})
        end || begin
          # defeat Ruby 2.5 lazy proc allocation to ensure
          # the methods below are passed the same proc instances
          # so `Hook` equality is preserved. For more info, see:
          # https://bugs.ruby-lang.org/issues/14045#note-5
          block.__id__

          add_hook_to_existing_matching_groups(meta, scope) { |g| g.append_after(scope, *meta, &block) }
          super(scope, *meta, &block)
        end
      end

      # Registers `block` as an `around` hook.
      #
      # See {Hooks#around} for full `around` hook docs.
      def around(scope=nil, *meta, &block)
        # defeat Ruby 2.5 lazy proc allocation to ensure
        # the methods below are passed the same proc instances
        # so `Hook` equality is preserved. For more info, see:
        # https://bugs.ruby-lang.org/issues/14045#note-5
        block.__id__

        add_hook_to_existing_matching_groups(meta, scope) { |g| g.around(scope, *meta, &block) }
        super(scope, *meta, &block)
      end

      # @private
      def with_suite_hooks
        return yield if dry_run?

        begin
          run_suite_hooks("a `before(:suite)` hook", @before_suite_hooks)
          yield
        ensure
          run_suite_hooks("an `after(:suite)` hook", @after_suite_hooks)
        end
      end

      # @private
      # Holds the various registered hooks. Here we use a FilterableItemRepository
      # implementation that is specifically optimized for the read/write patterns
      # of the config object.
      def hooks
        @hooks ||= HookCollections.new(self, FilterableItemRepository::QueryOptimized)
      end

      # Invokes block before defining an example group
      def on_example_group_definition(&block)
        on_example_group_definition_callbacks << block
      end

      # @api private
      # Returns an array of blocks to call before defining an example group
      def on_example_group_definition_callbacks
        @on_example_group_definition_callbacks ||= []
      end

      # @private
      def bisect_runner_class
        @bisect_runner_class ||= begin
          case bisect_runner
          when :fork
            RSpec::Support.require_rspec_core 'bisect/fork_runner'
            Bisect::ForkRunner
          when :shell
            RSpec::Support.require_rspec_core 'bisect/shell_runner'
            Bisect::ShellRunner
          else
            raise "Unsupported value for `bisect_runner` (#{bisect_runner.inspect}). " \
                  "Only `:fork` and `:shell` are supported."
          end
        end
      end

    private

      def load_file_handling_errors(method, file)
        __send__(method, file)
      rescue Support::AllExceptionsExceptOnesWeMustNotRescue => ex
        relative_file = Metadata.relative_path(file)
        reporter.notify_non_example_exception(ex, "An error occurred while loading #{relative_file}.")
        RSpec.world.wants_to_quit = true
      end

      def handle_suite_hook(scope, meta)
        return nil unless scope == :suite

        unless meta.empty?
          # TODO: in RSpec 4, consider raising an error here.
          # We warn only for backwards compatibility.
          RSpec.warn_with "WARNING: `:suite` hooks do not support metadata since " \
                          "they apply to the suite as a whole rather than " \
                          "any individual example or example group that has metadata. " \
                          "The metadata you have provided (#{meta.inspect}) will be ignored."
        end

        yield
      end

      def run_suite_hooks(hook_description, hooks)
        context = SuiteHookContext.new(hook_description, reporter)

        hooks.each do |hook|
          begin
            hook.run(context)
          rescue Support::AllExceptionsExceptOnesWeMustNotRescue => ex
            context.set_exception(ex)

            # Do not run subsequent `before` hooks if one fails.
            # But for `after` hooks, we run them all so that all
            # cleanup bits get a chance to complete, minimizing the
            # chance that resources get left behind.
            break if hooks.equal?(@before_suite_hooks)
          end
        end
      end

      def get_files_to_run(paths)
        files = FlatMap.flat_map(paths_to_check(paths)) do |path|
          path = path.gsub(File::ALT_SEPARATOR, File::SEPARATOR) if File::ALT_SEPARATOR
          File.directory?(path) ? gather_directories(path) : extract_location(path)
        end.uniq

        return files unless only_failures?
        relative_files = files.map { |f| Metadata.relative_path(File.expand_path f) }
        intersection = (relative_files & spec_files_with_failures.to_a)
        intersection.empty? ? files : intersection
      end

      def paths_to_check(paths)
        return paths if pattern_might_load_specs_from_vendored_dirs?
        paths + [Dir.getwd]
      end

      def pattern_might_load_specs_from_vendored_dirs?
        pattern.split(File::SEPARATOR).first.include?('**')
      end

      def gather_directories(path)
        include_files = get_matching_files(path, pattern)
        exclude_files = get_matching_files(path, exclude_pattern)
        (include_files - exclude_files).uniq
      end

      def get_matching_files(path, pattern)
        raw_files = Dir[file_glob_from(path, pattern)]
        raw_files.map { |file| File.expand_path(file) }.sort
      end

      def file_glob_from(path, pattern)
        stripped = "{#{pattern.gsub(/\s*,\s*/, ',')}}"
        return stripped if pattern =~ /^(\.\/)?#{Regexp.escape path}/ || absolute_pattern?(pattern)
        File.join(path, stripped)
      end

      if RSpec::Support::OS.windows?
        # :nocov:
        def absolute_pattern?(pattern)
          pattern =~ /\A[A-Z]:\\/ || windows_absolute_network_path?(pattern)
        end

        def windows_absolute_network_path?(pattern)
          return false unless ::File::ALT_SEPARATOR
          pattern.start_with?(::File::ALT_SEPARATOR + ::File::ALT_SEPARATOR)
        end
        # :nocov:
      else
        def absolute_pattern?(pattern)
          pattern.start_with?(File::Separator)
        end
      end

      def extract_location(path)
        match = /^(.*?)((?:\:\d+)+)$/.match(path)

        if match
          captures = match.captures
          path = captures[0]
          lines = captures[1][1..-1].split(":").map(&:to_i)
          filter_manager.add_location path, lines
        else
          path, scoped_ids = Example.parse_id(path)
          filter_manager.add_ids(path, scoped_ids.split(/\s*,\s*/)) if scoped_ids
        end

        return [] if path == default_path
        File.expand_path(path)
      end

      def command
        $0.split(File::SEPARATOR).last
      end

      def value_for(key)
        @preferred_options.fetch(key) { yield }
      end

      def define_built_in_hooks
        around(:example, :aggregate_failures => true) do |procsy|
          begin
            aggregate_failures(nil, :hide_backtrace => true, &procsy)
          rescue Support::AllExceptionsExceptOnesWeMustNotRescue => exception
            procsy.example.set_aggregate_failures_exception(exception)
          end
        end
      end

      def assert_no_example_groups_defined(config_option)
        return unless world.example_groups.any?

        raise MustBeConfiguredBeforeExampleGroupsError.new(
          "RSpec's #{config_option} configuration option must be configured before " \
          "any example groups are defined, but you have already defined a group."
        )
      end

      def output_wrapper
        @output_wrapper ||= OutputWrapper.new(output_stream)
      end

      def output_to_tty?(output=output_stream)
        output.respond_to?(:tty?) && output.tty?
      end

      def conditionally_disable_mocks_monkey_patching
        return unless disable_monkey_patching && rspec_mocks_loaded?

        RSpec::Mocks.configuration.tap do |config|
          config.syntax = :expect
          config.patch_marshal_to_support_partial_doubles = false
        end
      end

      def conditionally_disable_expectations_monkey_patching
        return unless disable_monkey_patching && rspec_expectations_loaded?

        RSpec::Expectations.configuration.syntax = :expect
      end

      def rspec_mocks_loaded?
        defined?(RSpec::Mocks.configuration)
      end

      def rspec_expectations_loaded?
        defined?(RSpec::Expectations.configuration)
      end

      def update_pattern_attr(name, value)
        if @spec_files_loaded
          RSpec.warning "Configuring `#{name}` to #{value} has no effect since " \
                        "RSpec has already loaded the spec files."
        end

        instance_variable_set(:"@#{name}", value)
        @files_to_run = nil
      end

      def clear_values_derived_from_example_status_persistence_file_path
        @last_run_statuses = nil
        @spec_files_with_failures = nil
      end

      def configure_group_with(group, module_list, application_method)
        module_list.items_for(group.metadata).each do |mod|
          __send__(application_method, mod, group)
        end
      end

      def add_hook_to_existing_matching_groups(meta, scope, &block)
        # For example hooks, we have to apply it to each of the top level
        # groups, even if the groups do not match. When we apply it, we
        # apply it with the metadata, so it will only apply to examples
        # in the group that match the metadata.
        # #2280 for background and discussion.
        if scope == :example || scope == :each || scope.nil?
          world.example_groups.each(&block)
        else
          meta = Metadata.build_hash_from(meta.dup)
          on_existing_matching_groups(meta, &block)
        end
      end

      def on_existing_matching_groups(meta)
        world.traverse_example_group_trees_until do |group|
          metadata_applies_to_group?(meta, group).tap do |applies|
            yield group if applies
          end
        end
      end

      def metadata_applies_to_group?(meta, group)
        meta.empty? || MetadataFilter.apply?(:any?, meta, group.metadata)
      end

      if RSpec::Support::RubyFeatures.module_prepends_supported?
        def safe_prepend(mod, host)
          host.__send__(:prepend, mod) unless host < mod
        end
      end

      if RUBY_VERSION.to_f >= 1.9
        def safe_include(mod, host)
          host.__send__(:include, mod) unless host < mod
        end

        def safe_extend(mod, host)
          host.extend(mod) unless host.singleton_class < mod
        end
      else # for 1.8.7
        # :nocov:
        def safe_include(mod, host)
          host.__send__(:include, mod) unless host.included_modules.include?(mod)
        end

        def safe_extend(mod, host)
          host.extend(mod) unless (class << host; self; end).included_modules.include?(mod)
        end
        # :nocov:
      end

      def define_mixed_in_module(mod, filters, mod_list, config_method, &block)
        unless Module === mod
          raise TypeError, "`RSpec.configuration.#{config_method}` expects a module but got: #{mod.inspect}"
        end

        meta = Metadata.build_hash_from(filters, :warn_about_example_group_filtering)
        mod_list.append(mod, meta)
        on_existing_matching_groups(meta, &block)
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
