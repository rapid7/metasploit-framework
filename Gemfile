source 'https://rubygems.org'

# Need 3+ for ActiveSupport::Concern
gem 'activesupport', '>= 3.0.0'
# Needed for some admin modules (scrutinizer_add_user.rb)
gem 'json'
# Needed by msfgui and other rpc components
gem 'msgpack'
# Needed by anemone crawler
gem 'nokogiri'
# Needed by anemone crawler
gem 'robots'
# Needed by db.rb and Msf::Exploit::Capture
gem 'packetfu', '1.1.9'

group :db do
	# Needed for Msf::DbManager
	gem 'activerecord'
	# Database models shared between framework and Pro.
	gem 'metasploit_data_models', '~> 0.16.6'
	# Needed for module caching in Mdm::ModuleDetails
	gem 'pg', '>= 0.11'
end

group :pcap do
  gem 'network_interface', '~> 0.0.1'
	# For sniffer and raw socket modules
	gem 'pcaprub'
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
# Make rspec output shorter and more useful
	gem 'fivemat', '1.2.1'
	# running documentation generation tasks and rspec tasks
	gem 'rake', '>= 10.0.0'
end

group :test do
	# Removes records from database created during tests.  Can't use rspec-rails'
	# transactional fixtures because multiple connections are in use so
	# transactions won't work.
	gem 'database_cleaner'
	# testing framework
	gem 'rspec', '>= 2.12'
	gem 'shoulda-matchers'
	# code coverage for tests
	# any version newer than 0.5.4 gives an Encoding error when trying to read the source files.
	# see: https://github.com/colszowka/simplecov/issues/127 (hopefully fixed in 0.8.0)
	gem 'simplecov', '0.5.4', :require => false
	# Manipulate Time.now in specs
	gem 'timecop'
end
