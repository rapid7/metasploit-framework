source 'http://rubygems.org'

# Need 3+ for ActiveSupport::Concern
gem 'activesupport', '>= 3.0.0'
# Needed for Msf::DbManager
gem 'activerecord'
# Database models shared between framework and Pro.
gem 'metasploit_data_models', :git => 'git://github.com/rapid7/metasploit_data_models.git', :tag => '0.3.0'
# Needed for module caching in Mdm::ModuleDetails
gem 'pg', '>= 0.11'

group :development do
  # Markdown formatting for yard
  gem 'redcarpet'
  # generating documentation
  gem 'yard'
end

group :development, :test do
  # running documentation generation tasks and rspec tasks
  gem 'rake'
end

group :test do
  # testing framework
  gem 'rspec', '>= 2.12'
  # code coverage for tests
  # any version newer than 0.5.4 gives an Encoding error when trying to read the source files.
  gem 'simplecov', '0.5.4', :require => false
end
