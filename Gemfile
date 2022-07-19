source 'https://rubygems.org'
# Add default group gems to `metasploit-framework.gemspec`:
#   spec.add_runtime_dependency '<name>', [<version requirements>]
gemspec name: 'metasploit-framework'

gem 'ruby_smb', github: 'adfoster-r7/ruby_smb', branch: 'run-ubuntu-22.04-in-test-matrix'
gem 'hrr_rb_ssh', github: 'adfoster-r7/hrr_rb_ssh', branch: 'investigate-openssl3-support'
gem 'openssl-ccm', github: 'adfoster-r7/openssl-ccm', branch: 'add-support-openssl-3'
gem 'openssl-cmac', github: 'adfoster-r7/openssl-cmac', branch: 'add-support-for-openssl3'
gem 'metasploit-credential', github: 'adfoster-r7/metasploit-credential', branch: 'add-support-for-openssl3'

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
  # module documentation
  gem 'octokit'
  # memory profiling
  gem 'memory_profiler'
  # cpu profiling
  gem 'ruby-prof', '1.4.2'
  # Metasploit::Aggregator external session proxy
  # disabled during 2.5 transition until aggregator is available
  #gem 'metasploit-aggregator'
end

group :development, :test do
  # automatically include factories from spec/factories
  gem 'factory_bot_rails'
  # Make rspec output shorter and more useful
  gem 'fivemat'
  # running documentation generation tasks and rspec tasks
  gem 'rake'
  # Define `rake spec`.  Must be in development AND test so that its available by default as a rake test when the
  # environment is development
  gem 'rspec-rails'
  gem 'rspec-rerun'
  gem 'rubocop'
end

group :test do
  # Manipulate Time.now in specs
  gem 'timecop'
end

