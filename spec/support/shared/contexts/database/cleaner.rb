# -*- coding:binary -*-
require 'metasploit/framework/database'

shared_context 'database cleaner' do |options={}|
  options.assert_valid_keys(:after)

  scope = options.fetch(:after, :each)

  def with_established_connection
    remove_connection = false

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
      # allow with_established_connection to be reentrant so that it can be called in nested blocks: only the outer most
      # block that actually creates the connection will remove it.
      remove_connection = true

      retry
    ensure
      # remove the established connection so that it doesn't leak into another
      # example
      if remove_connection
        ActiveRecord::Base.remove_connection
      end
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
  after(scope) do
    with_established_connection do
      # Testing using both :truncation and :deletion; :truncation took long
      # for testing.
      DatabaseCleaner.clean_with(:deletion)
    end
  end
end
