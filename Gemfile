source 'https://rubygems.org'
# Add default group gems to `metasploit-framework.gemspec`:
#   spec.add_runtime_dependency '<name>', [<version requirements>]
gemspec name: 'metasploit-framework'

# separate from test as simplecov is not run on travis-ci
group :coverage do
  # code coverage for tests
  gem 'simplecov', '0.18.2'
end

group :development do
  # Markdown formatting for yard
  gem 'redcarpet'
  # generating documentation
  gem 'yard'
  # for development and testing purposes
  gem 'pry-byebug'
  # Ruby Debugging Library - rebuilt and included by default from Ruby 3.1 onwards.
  # Replaces the old lib/debug.rb and provides more features.
  gem 'debug', '>= 1.0.0'
  # module documentation
  gem 'octokit'
  # memory profiling
  gem 'memory_profiler'
  # cpu profiling
  gem 'ruby-prof'
  # Metasploit::Aggregator external session proxy
  # disabled during 2.5 transition until aggregator is available
  # gem 'metasploit-aggregator'
end

group :development, :test do
  # For ./tools/dev/update_gem_licenses.sh
  gem 'license_finder', '5.11.1'
  # running documentation generation tasks and rspec tasks
  gem 'rake'
  # Define `rake spec`.  Must be in development AND test so that its available by default as a rake test when the
  # environment is development
  gem 'rspec-rails'
  gem 'rspec-rerun'
  # Required during CI as well local development
  gem 'rubocop', '1.75.7'
end

group :test do
  # automatically include factories from spec/factories
  gem 'test-prof'
  gem 'factory_bot_rails'
  # Make rspec output shorter and more useful
  gem 'fivemat'
  # rspec formatter for acceptance tests
  gem 'allure-rspec'
  # Manipulate Time.now in specs
  gem 'timecop'
end

