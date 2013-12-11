module Metasploit::Framework::Spec::ActiveRecord
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.before(:suite) do
          ::ActiveRecord::Base.configurations = Metasploit::Framework::Database.configurations
          spec = ::ActiveRecord::Base.configurations[Metasploit::Framework.env]
          ::ActiveRecord::Base.establish_connection(spec)
        end

        config.before(:all, :without_established_connection) do
          # remove and preserve the background connection for the suite
          @removed_connection = ::ActiveRecord::Base.remove_connection

          unless @removed_connection
            fail "Suite connection lost"
          end
        end

        config.after(:each, :without_established_connection) do
          # remove any connection by the tested code so it doesn't interfere with next connection test
          ::ActiveRecord::Base.remove_connection
        end

        config.after(:all, :without_established_connection) do
          # restore the preserved background connection for the suite
          ::ActiveRecord::Base.establish_connection(@removed_connection)
        end
      end

      @configured = true
    end
  end
end