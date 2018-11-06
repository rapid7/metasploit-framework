source "https://rubygems.org"

# Specify your gem's dependencies in metasploit_data_models.gemspec
gemspec


group :development do
  #gem 'metasploit-erd'
  # embed ERDs on index, namespace Module and Class<ActiveRecord::Base> pages
  #gem 'yard-metasploit-erd'
end

# used by dummy application
group :development, :test do
  # Upload coverage reports to coveralls.io
  gem 'coveralls', require: false  
  # supplies factories for producing model instance for specs
  # Version 4.1.0 or newer is needed to support generate calls without the 'FactoryBot.' in factory definitions syntax.
  gem 'factory_bot'
  # auto-load factories from spec/factories
  gem 'factory_bot_rails'

  gem 'rails', '~>4.2.6'
  # Used to create fake data
  gem "faker"
end

group :test do
  # In a full rails project, factory_girl_rails would be in both the :development, and :test group, but since we only
  # want rails in :test, factory_girl_rails must also only be in :test.
  # add matchers from shoulda, such as validates_presence_of, which are useful for testing validations
  gem 'shoulda-matchers'
  # code coverage of tests
  gem 'simplecov', :require => false
  # need rspec-rails >= 2.12.0 as 2.12.0 adds support for redefining named subject in nested context that uses the
  # named subject from the outer context without causing a stack overflow.
  gem 'rspec-rails'
  # used for building markup for webpage factories
  gem 'builder'
end
