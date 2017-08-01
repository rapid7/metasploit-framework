source 'https://rubygems.org'
# Add default group gems to `metasploit-framework.gemspec`:
#   spec.add_runtime_dependency '<name>', [<version requirements>]
gemspec name: 'metasploit-framework'

# These pull in pre-release gems in order to fix specific issues.
# XXX https://github.com/alexdalitz/dnsruby/pull/134
gem 'dnsruby', git: 'https://github.com/alexdalitz/dnsruby'

# XXX https://github.com/ConnorAtherton/rb-readline/commit/fd882edcd145c26681f9971be5f6675c7f6d1970
gem 'rb-readline', git: 'https://github.com/ConnorAtherton/rb-readline' if [
 'x86_64-linux', 'x86-linux', 'darwin'].include?(RUBY_PLATFORM.gsub(/.*darwin.*/, 'darwin'))

# separate from test as simplecov is not run on travis-ci
group :coverage do
  # code coverage for tests
  gem 'simplecov'
end

group :development do
  # Markdown formatting for yard
  gem 'redcarpet'
  # generating documentation
  gem 'yard'
  # for development and testing purposes
  gem 'pry'
  # module documentation
  gem 'octokit'
  # metasploit-aggregator as a framework only option for now
  # Metasploit::Aggregator external session proxy
  gem 'metasploit-aggregator'
end

group :development, :test do
  # automatically include factories from spec/factories
  gem 'factory_girl_rails'
  # Make rspec output shorter and more useful
  gem 'fivemat'
  # running documentation generation tasks and rspec tasks
  gem 'rake'
  # Define `rake spec`.  Must be in development AND test so that its available by default as a rake test when the
  # environment is development
  gem 'rspec-rails'
  gem 'rspec-rerun'
end

group :test do
  # Manipulate Time.now in specs
  gem 'timecop'
end
