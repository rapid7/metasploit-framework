# rubocop:disable Style/GlobalVars
$_rspec_core_load_started_at = Time.now
# rubocop:enable Style/GlobalVars

require "rspec/support"
RSpec::Support.require_rspec_support "caller_filter"

RSpec::Support.define_optimized_require_for_rspec(:core) { |f| require_relative f }

%w[
  version
  warnings

  set
  flat_map
  filter_manager
  dsl
  notifications
  reporter

  hooks
  memoized_helpers
  metadata
  metadata_filter
  pending
  formatters
  ordering

  world
  configuration
  option_parser
  configuration_options
  runner
  invocations
  example
  shared_example_group
  example_group
].each { |name| RSpec::Support.require_rspec_core name }

# Namespace for all core RSpec code.
module RSpec
  autoload :SharedContext, 'rspec/core/shared_context'

  extend RSpec::Core::Warnings

  class << self
    # Setters for shared global objects
    # @api private
    attr_writer :configuration, :world
  end

  # Used to ensure examples get reloaded and user configuration gets reset to
  # defaults between multiple runs in the same process.
  #
  # Users must invoke this if they want to have the configuration reset when
  # they use the runner multiple times within the same process. Users must deal
  # themselves with re-configuration of RSpec before run.
  def self.reset
    RSpec::ExampleGroups.remove_all_constants
    @world = nil
    @configuration = nil
  end

  # Used to ensure examples get reloaded between multiple runs in the same
  # process and ensures user configuration is persisted.
  #
  # Users must invoke this if they want to clear all examples but preserve
  # current configuration when they use the runner multiple times within the
  # same process.
  def self.clear_examples
    world.reset
    configuration.reset_reporter
    configuration.start_time = ::RSpec::Core::Time.now
    configuration.reset_filters
  end

  # Returns the global [Configuration](RSpec/Core/Configuration) object. While
  # you _can_ use this method to access the configuration, the more common
  # convention is to use [RSpec.configure](RSpec#configure-class_method).
  #
  # @example
  #     RSpec.configuration.drb_port = 1234
  # @see RSpec.configure
  # @see Core::Configuration
  def self.configuration
    @configuration ||= RSpec::Core::Configuration.new
  end

  # Yields the global configuration to a block.
  # @yield [Configuration] global configuration
  #
  # @example
  #     RSpec.configure do |config|
  #       config.add_formatter 'documentation'
  #     end
  # @see Core::Configuration
  def self.configure
    yield configuration if block_given?
  end

  # The example being executed.
  #
  # The primary audience for this method is library authors who need access
  # to the example currently being executed and also want to support all
  # versions of RSpec 2 and 3.
  #
  # @example
  #
  #     RSpec.configure do |c|
  #       # context.example is deprecated, but RSpec.current_example is not
  #       # available until RSpec 3.0.
  #       fetch_current_example = RSpec.respond_to?(:current_example) ?
  #         proc { RSpec.current_example } : proc { |context| context.example }
  #
  #       c.before(:example) do
  #         example = fetch_current_example.call(self)
  #
  #         # ...
  #       end
  #     end
  #
  def self.current_example
    RSpec::Support.thread_local_data[:current_example]
  end

  # Set the current example being executed.
  # @api private
  def self.current_example=(example)
    RSpec::Support.thread_local_data[:current_example] = example
  end

  # @private
  # Internal container for global non-configuration data.
  def self.world
    @world ||= RSpec::Core::World.new
  end

  # Namespace for the rspec-core code.
  module Core
    autoload :ExampleStatusPersister, "rspec/core/example_status_persister"
    autoload :Profiler,               "rspec/core/profiler"

    # @private
    # This avoids issues with reporting time caused by examples that
    # change the value/meaning of Time.now without properly restoring
    # it.
    class Time
      class << self
        define_method(:now, &::Time.method(:now))
      end
    end

    # @private path to executable file.
    def self.path_to_executable
      @path_to_executable ||= File.expand_path('../../../exe/rspec', __FILE__)
    end
  end

  # @private
  MODULES_TO_AUTOLOAD = {
    :Matchers     => "rspec/expectations",
    :Expectations => "rspec/expectations",
    :Mocks        => "rspec/mocks"
  }

  # @private
  def self.const_missing(name)
    # Load rspec-expectations when RSpec::Matchers is referenced. This allows
    # people to define custom matchers (using `RSpec::Matchers.define`) before
    # rspec-core has loaded rspec-expectations (since it delays the loading of
    # it to allow users to configure a different assertion/expectation
    # framework). `autoload` can't be used since it works with ruby's built-in
    # require (e.g. for files that are available relative to a load path dir),
    # but not with rubygems' extended require.
    #
    # As of rspec 2.14.1, we no longer require `rspec/mocks` and
    # `rspec/expectations` when `rspec` is required, so we want
    # to make them available as an autoload.
    require MODULES_TO_AUTOLOAD.fetch(name) { return super }
    ::RSpec.const_get(name)
  end

  Core::DSL.expose_globally!
  Core::SharedExampleGroup::TopLevelDSL.expose_globally!
end
