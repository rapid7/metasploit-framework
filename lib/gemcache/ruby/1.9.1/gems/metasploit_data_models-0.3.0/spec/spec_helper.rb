# Configure Rails Environment
ENV['RAILS_ENV'] = 'test'

require File.expand_path('../dummy/config/environment.rb',  __FILE__)

require 'rubygems'
require 'bundler'
Bundler.setup(:default, :test)
Bundler.require(:default, :test)

# full backtrace in logs so its easier to trace errors
Rails.backtrace_cleaner.remove_silencers!

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.
support_glob = MetasploitDataModels.root.join('spec', 'support', '**', '*.rb')

Dir.glob(support_glob) do |path|
  require path
end

RSpec.configure do |config|
  config.mock_with :rspec
end
