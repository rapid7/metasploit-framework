source 'https://rubygems.org'

# Need 3+ for ActiveSupport::Concern
gem 'activesupport', '>= 3.0.0', '< 4.0.0'
# Needed for some admin modules (cfme_manageiq_evm_pass_reset.rb)
gem 'bcrypt'
# Needed for some admin modules (scrutinizer_add_user.rb)
gem 'json'
# Needed by msfgui and other rpc components
gem 'msgpack'
# Needed by anemone crawler
gem 'nokogiri'
# Needed by db.rb and Msf::Exploit::Capture
gem 'packetfu', '1.1.9'
# Run initializers for metasploit-concern, metasploit-credential, metasploit_data_models Rails::Engines
gem 'railties'
# Needed by JSObfu
gem 'rkelly-remix', '0.0.6'
# Needed by anemone crawler
gem 'robots'
# required for Time::TZInfo in ActiveSupport
gem 'tzinfo'
# Needed for some post modules
gem 'sqlite3'

group :db do
  # Needed for Msf::DbManager
  gem 'activerecord', '>= 3.0.0', '< 4.0.0'
  # Metasploit::Creential database models
  gem 'metasploit-credential', git: 'github-metasploit-credential:rapid7/metasploit-credential.git', tag: 'v0.1.2-metasploit-credential'
  # Database models shared between framework and Pro.
  gem 'metasploit_data_models', '~> 0.17.1'
  # Needed for module caching in Mdm::ModuleDetails
  gem 'pg', '>= 0.11'
end

group :development do
  # Markdown formatting for yard
  gem 'redcarpet'
  # generating documentation
  gem 'yard'
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
  gem 'rspec', '>= 2.12'
  # Define `rake spec`.  Must be in development AND test so that its available by default as a rake test when the
  # environment is development
  gem 'rspec-rails'
end

group :pcap do
  gem 'network_interface', '~> 0.0.1'
  # For sniffer and raw socket modules
  gem 'pcaprub'
end

group :test do
  gem 'shoulda-matchers'
  # code coverage for tests
  # any version newer than 0.5.4 gives an Encoding error when trying to read the source files.
  # see: https://github.com/colszowka/simplecov/issues/127 (hopefully fixed in 0.8.0)
  gem 'simplecov', '0.5.4', :require => false
  # Manipulate Time.now in specs
  gem 'timecop'
end
