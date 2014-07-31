# -*- coding: binary -*-
ENV['RAILS_ENV'] = 'test'

require 'simplecov'

# @note must be before loading config/environment because railtie needs to be loaded before
#   `Metasploit::Framework::Application.initialize!` is called.
#
# Must be explicit as activerecord is optional dependency
require 'active_record/railtie'

require File.expand_path('../../config/environment', __FILE__)

# Don't `require 'rspec/rails'` as it includes support for pieces of rails that metasploit-framework doesn't use
require 'rspec/core'
require 'rails/version'
require 'rspec/rails/adapters'
require 'rspec/rails/extensions'
require 'rspec/rails/fixture_support'
require 'rspec/rails/matchers'
require 'rspec/rails/mocks'

FILE_FIXTURES_PATH = File.expand_path(File.dirname(__FILE__)) + '/file_fixtures/'

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.
Dir[Rails.root.join('spec', 'support', '**', '*.rb')].each do |f|
  require f
end

RSpec.configure do |config|
  config.mock_with :rspec

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = 'random'

  # If you're not using ActiveRecord, or you'd prefer not to run each of your
  # examples within a transaction, remove the following line or assign false
  # instead of true.
  config.use_transactional_fixtures = true
end
