# -*- coding:binary -*-
require 'metasploit/framework/database'

shared_context 'DatabaseCleaner' do
	def with_established_connection
		begin
			ActiveRecord::Base.connection_pool.with_connection do
				yield
			end
		rescue ActiveRecord::ConnectionNotEstablished
			# if there isn't a connection established, then established one and try
			# again
			ActiveRecord::Base.configurations = Metasploit::Framework::Database.configurations
			spec = ActiveRecord::Base.configurations[Metasploit::Framework.env]
			ActiveRecord::Base.establish_connection(spec)

			retry
		ensure
			# remove the established connection so that it doesn't leak into another
			# example
			ActiveRecord::Base.remove_connection
		end
	end

	# clean before all in case last test run was interrupted before
	# after(:each) could clean up
	before(:all) do
		with_established_connection do
			DatabaseCleaner.clean_with(:truncation)
		end
	end

	# Clean up after each test
	after(:each) do
		with_established_connection do
			# Testing using both :truncation and :deletion; :truncation took long
			# for testing.
			DatabaseCleaner.clean_with(:deletion)
		end
	end
end
