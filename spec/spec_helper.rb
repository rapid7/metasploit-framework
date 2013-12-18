# -*- coding:binary -*-
require 'rubygems'
require 'bundler'
Bundler.require(:default, :test, :db)

ENV['METASPLOIT_FRAMEWORK_ENV'] = 'test'

FILE_FIXTURES_PATH = File.expand_path(File.dirname(__FILE__)) + "/file_fixtures/"

# add project lib directory to load path
spec_pathname = Pathname.new(__FILE__).dirname
root_pathname = spec_pathname.join('..').expand_path
lib_pathname = root_pathname.join('lib')
$LOAD_PATH.unshift(lib_pathname.to_s)

# must be first require and started before any other requires so that it can measure coverage of all following required
# code.  It is after the rubygems and bundler only because Bundler.setup supplies the LOAD_PATH to simplecov.
require 'simplecov'

# now that simplecov is loaded, load everything else
require 'metasploit/framework'
require 'rspec/core'

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.

support_globs = Metasploit::Framework::Spec::ROOTED_MODULES.collect { |rooted|
	rooted.root.join('spec', 'support', '**', '*.rb')
}

support_globs.each do |support_glob|
	Dir.glob(support_glob) do |path|
		require path
	end
end

# Use a strict sanitizer to prevent wasting time trying to figure out why associations are nil after being built.  This
# would normally be set in Rails in development.rb and test.rb environment files using
# `config.active_record.mass_assignment_santizer = :strict`
ActiveRecord::Base.mass_assignment_sanitizer = :strict

# Temporary fix for FiveMat RSpec incompatibility
# @see https://github.com/tpope/fivemat/issues/14
RSpec::Core::PendingExampleFixedError = RSpec::Core::Pending::PendingExampleFixedError

RSpec.configure do |config|
  config.mock_with :rspec
  config.order = :random
  config.treat_symbols_as_metadata_keys_with_true_values = true
end

# Adds to RSpec configuration for different subsystems
Metasploit::Framework::Spec.configure!
