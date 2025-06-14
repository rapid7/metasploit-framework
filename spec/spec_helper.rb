# -*- coding: binary -*-

# Enable legacy providers such as blowfish-cbc, cast128-cbc, arcfour, etc
$stderr.puts "Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions." unless ENV['OPENSSL_CONF'].nil?
ENV['OPENSSL_CONF'] = File.expand_path(
  File.join(File.dirname(__FILE__), '..', 'config', 'openssl.conf')
)

require 'stringio'
require 'factory_bot'
require 'rubocop'
require 'rubocop/rspec/support'
require 'faker'

# Monkey patch rubocop which fails to load the default rspec config due to encoding issues - https://github.com/rapid7/metasploit-framework/pull/20196
# Caused by our global IO encoding being set to ASCII-8BIT - https://github.com/rapid7/metasploit-framework/blob/b251fc1b635dc07c66cc3848983bdcbeaa08a81f/lib/metasploit/framework/common_engine.rb#L25-L33
# Original code: https://github.com/rubocop/rubocop/blob/b6c9b0ed31daf40be5a273714095e451aee10bcd/lib/rubocop/config_loader.rb#L275
# Character which causes encoding failure: https://github.com/rubocop/rubocop/blob/b6c9b0ed31daf40be5a273714095e451aee10bcd/config/default.yml#L3298-L3305
module RuboCop
  class ConfigLoader
     # Read the specified file, or exit with a friendly, concise message on
     # stderr. Care is taken to use the standard OS exit code for a "file not
     # found" error.
     def self.read_file(absolute_path)
       File.binread(absolute_path).force_encoding(Encoding::UTF_8)
     rescue Errno::ENOENT
       raise ConfigNotFoundError, "Configuration file not found: #{absolute_path}"
     end
  end
end

ENV['RAILS_ENV'] = 'test'

load_metasploit = ENV.fetch('SPEC_HELPER_LOAD_METASPLOIT', 'true') == 'true'

if load_metasploit
  # @note must be before loading config/environment because railtie needs to be loaded before
  #   `Metasploit::Framework::Application.initialize!` is called.
  #
  # Must be explicit as activerecord is optional dependency
  require 'active_record/railtie'
  require 'metasploit/framework/database'
  # check if database.yml is present
  unless Metasploit::Framework::Database.configurations_pathname.try(:to_path)
    fail 'RSPEC currently needs a configured database'
  end

  require File.expand_path('../../config/environment', __FILE__)

  # Don't `require 'rspec/rails'` as it includes support for pieces of rails that metasploit-framework doesn't use
  require 'rspec/rails'

  require 'metasploit/framework/spec'

  FILE_FIXTURES_PATH = File.expand_path(File.dirname(__FILE__)) + '/file_fixtures/'

  # Load the shared examples from the following engines
  engines = [
    Metasploit::Concern,
    Rails
  ]

  # Requires supporting ruby files with custom matchers and macros, etc,
  # in spec/support/ and its subdirectories.
  engines.each do |engine|
    support_glob = engine.root.join('spec', 'support', '**', '*.rb')
    Dir[support_glob].each { |f|
      require f
    }
  end

  # Fail the test suite if the test environment database has not been migrated
  migration_manager = Class.new.extend(Msf::DBManager::Migration)
  fail "Run `RAILS_ENV=test rake db:migrate` before running tests" if migration_manager.needs_migration?
end

RSpec.configure do |config|
  config.raise_errors_for_deprecations!
  config.include RuboCop::RSpec::ExpectOffense
  config.expose_dsl_globally = false

  # Don't run Acceptance tests by default
  config.define_derived_metadata(file_path: %r{spec/acceptance/}) do |metadata|
    metadata[:acceptance] ||= true
  end
  config.filter_run_excluding({ acceptance: true })

  # These two settings work together to allow you to limit a spec run
  # to individual examples or groups you care about by tagging them with
  # `:focus` metadata. When nothing is tagged with `:focus`, all examples
  # get run.
  if ENV['CI']
    config.before(:example, :focus) { raise "Should not commit focused specs" }
  else
    config.filter_run focus: true
    config.run_all_when_everything_filtered = true
  end

  # allow more verbose output when running an individual spec file.
  if config.files_to_run.one?
    # RSpec filters the backtrace by default so as not to be so noisy.
    # This causes the full backtrace to be printed when running a single
    # spec file (e.g. to troubleshoot a particular spec failure).
    config.full_backtrace = true
  end

  # Print the 10 slowest examples and example groups at the
  # end of the spec run, to help surface which specs are running
  # particularly slow.
  config.profile_examples = 10

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = :random

  if load_metasploit
    config.use_transactional_fixtures = true

    # rspec-rails 3 will no longer automatically infer an example group's spec type
    # from the file location. You can explicitly opt-in to the feature using this
    # config option.
    # To explicitly tag specs without using automatic inference, set the `:type`
    # metadata manually:
    #
    #     describe ThingsController, :type => :controller do
    #       # Equivalent to being in spec/controllers
    #     end
    config.infer_spec_type_from_file_location!
  end

  # Seed global randomization in this process using the `--seed` CLI option.
  # Setting this allows you to use `--seed` to deterministically reproduce
  # test failures related to randomization by passing the same `--seed` value
  # as the one that triggered the failure.
  Kernel.srand config.seed

  # Implemented to avoid regression issue with code calling Faker not being deterministic
  # https://github.com/faker-ruby/faker/issues/2281
  Faker::Config.random = Random.new(config.seed)

  config.expect_with :rspec do |expectations|
    # Enable only the newer, non-monkey-patching expect syntax.
    expectations.syntax = :expect
  end

  # rspec-mocks config goes here. You can use an alternate test double
  # library (such as bogus or mocha) by changing the `mock_with` option here.
  config.mock_with :rspec do |mocks|
    # Enable only the newer, non-monkey-patching expect syntax.
    # For more details, see:
    #   - http://teaisaweso.me/blog/2013/05/27/rspecs-new-message-expectation-syntax/
    mocks.syntax = :expect

    mocks.patch_marshal_to_support_partial_doubles = false

    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object.
    mocks.verify_partial_doubles = true
  end

  if ENV['REMOTE_DB']
    require 'metasploit/framework/data_service/remote/managed_remote_data_service'
    opts = {}
    opts[:process_name] = File.join('tools', 'dev', 'msfdb_ws')
    opts[:host] = 'localhost'
    opts[:port] = '8080'

    config.before(:suite) do
      Metasploit::Framework::DataService::ManagedRemoteDataService.instance.start(opts)
    end

    config.after(:suite) do
      Metasploit::Framework::DataService::ManagedRemoteDataService.instance.stop
    end
  end

  if ENV['MSF_FEATURE_DEFER_MODULE_LOADS']
    config.before(:suite) do
      Msf::FeatureManager.instance.set(Msf::FeatureManager::DEFER_MODULE_LOADS, true)
    end
  end

  # rex-text table performs word wrapping on msfconsole tables:
  #   https://github.com/rapid7/rex-text/blob/11e59416f7d8cce18b8b8b9893b3277e6ad0bea1/lib/rex/text/wrapped_table.rb#L74
  # This can cause some integration tests to fail if the tests are run from smaller consoles
  # This mock will ensure that the tests run without word-wrapping.
  require 'bigdecimal'
  config.before(:each) do
    mock_io_console = double(:console, winsize: { rows: 30, columns: ::BigDecimal::INFINITY }.values)
    allow(::IO).to receive(:console).and_return(mock_io_console)
  end
end

if load_metasploit
  Metasploit::Framework::Spec::Constants::Suite.configure!
  Metasploit::Framework::Spec::Threads::Suite.configure!
end

def get_stdout(&block)
  out = $stdout
  $stdout = tmp = StringIO.new
  begin
    yield
  ensure
    $stdout = out
  end
  tmp.string
end

def get_stderr(&block)
  out = $stderr
  $stderr = tmp = StringIO.new
  begin
    yield
  ensure
    $stderr = out
  end
  tmp.string
end
