source 'https://rubygems.org'
# Add default group gems to `metasploit-framework.gemspec`:
#   spec.add_runtime_dependency '<name>', [<version requirements>]
gemspec

group :db do
  # Needed for Msf::DbManager
  gem 'activerecord', '>= 3.0.0', '< 4.0.0'

  # Metasploit::Credential database models
  gem 'metasploit-credential', '~> 0.12.0'
  # Database models shared between framework and Pro.
  gem 'metasploit_data_models', '~> 0.21.1'
  # Needed for module caching in Mdm::ModuleDetails
  gem 'pg', '>= 0.11'
end

group :development do
  # Markdown formatting for yard
  gem 'redcarpet'
  # generating documentation
  gem 'yard'
  # for development and testing purposes
  gem 'pry'
end

group :development, :test do
  # supplies factories for producing model instance for specs
  # Version 4.1.0 or newer is needed to support generate calls without the
  # 'FactoryGirl.' in factory definitions syntax.
  gem 'factory_girl', '>= 4.1.0'
  # automatically include factories from spec/factories
  gem 'factory_girl_rails'
  # Make rspec output shorter and more useful
  gem 'fivemat', '1.2.1'
  # running documentation generation tasks and rspec tasks
  gem 'rake', '>= 10.0.0'
  # testing framework
  gem 'rspec', '>= 2.12', '< 3.0.0'
  # Define `rake spec`.  Must be in development AND test so that its available by default as a rake test when the
  # environment is development
  gem 'rspec-rails' , '>= 2.12', '< 3.0.0'
end

group :pcap do
  gem 'network_interface', '~> 0.0.1'
  # For sniffer and raw socket modules
  gem 'pcaprub'
end

group :test do
  # cucumber extension for testing command line applications, like msfconsole
  gem 'aruba'
  # cucumber + automatic database cleaning with database_cleaner
  gem 'cucumber-rails', :require => false
  gem 'shoulda-matchers'
  # code coverage for tests
  # any version newer than 0.5.4 gives an Encoding error when trying to read the source files.
  # see: https://github.com/colszowka/simplecov/issues/127 (hopefully fixed in 0.8.0)
  gem 'simplecov', '0.5.4', :require => false
  # Manipulate Time.now in specs
  gem 'timecop'
end
