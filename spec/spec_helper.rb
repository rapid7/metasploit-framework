# -*- coding: binary -*-
require 'stringio'
require 'factory_bot'

ENV['RAILS_ENV'] = 'test'

require File.expand_path('../../config/rails_bigdecimal_fix', __FILE__)

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

RSpec.configure do |config|
  config.raise_errors_for_deprecations!

  config.expose_dsl_globally = false

  # These two settings work together to allow you to limit a spec run
  # to individual examples or groups you care about by tagging them with
  # `:focus` metadata. When nothing is tagged with `:focus`, all examples
  # get run.
  config.filter_run :focus
  config.run_all_when_everything_filtered = true

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

  config.use_transactional_fixtures = true

  # Seed global randomization in this process using the `--seed` CLI option.
  # Setting this allows you to use `--seed` to deterministically reproduce
  # test failures related to randomization by passing the same `--seed` value
  # as the one that triggered the failure.
  Kernel.srand config.seed

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

end

Metasploit::Framework::Spec::Constants::Suite.configure!
Metasploit::Framework::Spec::Threads::Suite.configure!

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
