source 'https://rubygems.org'
# Add default group gems to `metasploit-framework.gemspec`:
#   spec.add_runtime_dependency '<name>', [<version requirements>]
gemspec name: 'metasploit-framework'

# separate from test as simplecov is not run on travis-ci
group :coverage do
  # code coverage for tests
  # any version newer than 0.5.4 gives an Encoding error when trying to read the source files.
  # see: https://github.com/colszowka/simplecov/issues/127 (hopefully fixed in 0.8.0)
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
  gem 'octokit', '~> 4.0'
  # rails-upgrade staging gems
  gem 'metasploit-aggregator', git: 'git@github.com:rapid7/metasploit-aggregator', branch: "master"
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
end

group :test do
  # cucumber extension for testing command line applications, like msfconsole
  gem 'aruba'
  # cucumber + automatic database cleaning with database_cleaner
  gem 'cucumber-rails', :require => false
  gem 'shoulda-matchers'
  # Manipulate Time.now in specs
  gem 'timecop'
end
