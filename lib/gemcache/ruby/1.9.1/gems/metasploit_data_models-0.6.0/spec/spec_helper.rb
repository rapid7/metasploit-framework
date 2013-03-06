# Configure Rails Environment
ENV['RAILS_ENV'] = 'test'

require File.expand_path('../dummy/config/environment.rb',  __FILE__)
require 'rspec/rails'
require 'rspec/autorun'

require 'rubygems'
require 'bundler'
Bundler.setup(:default, :test)
Bundler.require(:default, :test)

# full backtrace in logs so its easier to trace errors
Rails.backtrace_cleaner.remove_silencers!

require 'simplecov'

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.
support_glob = MetasploitDataModels.root.join('spec', 'support', '**', '*.rb')

Dir.glob(support_glob) do |path|
  require path
end

RSpec.configure do |config|
  config.before(:each) do
    # Rex is only available when testing with metasploit-framework or pro, so stub out the methods that require it
    Mdm::Workspace.any_instance.stub(:valid_ip_or_range? => true)
  end

  config.mock_with :rspec
  config.use_transactional_fixtures = true
  config.order = :random
end
