require 'msfdb_helpers/db_interface'
module MsfdbHelpers
  class Standalone < DbInterface

    def initialize(options:, db_conf:, connection_string:)
      @options = options
      @db_conf = db_conf
      begin
        @conn = PG.connect(connection_string)
      rescue PG::ConnectionBad
        print_error('Could not connect to standalone PostgreSQL instance. Ensure that the connection string is valid, and that the database is accessible')
        raise
      end

      conninfo = @conn.conninfo_hash
      @options[:db_port] = conninfo[:port]
      @options[:db_host] = conninfo[:host]
      super(options)
    end

    def init(msf_pass, msftest_pass)
      create_db_users(msf_pass, msftest_pass)
    end

    def delete
      @conn.exec("DROP DATABASE IF EXISTS #{@options[:msf_db_name]};")
      @conn.exec("DROP DATABASE IF EXISTS #{@options[:msftest_db_name]};")
      @conn.exec("DROP USER IF EXISTS #{@options[:msf_db_user]};")
      @conn.exec("DROP USER IF EXISTS #{@options[:msftest_db_user]};")
      FileUtils.rm_r(@db_conf, force: true)
    end

    def start
      true
    end

    def stop
      puts 'A standalone database cannot be stopped by msfdb'
      false
    end

    def restart
      raise NotImplementedError
    end

    def exists?
      !@conn.nil?
    end

    def status
      # Search for the database name
      is_initialized = @conn.exec_params('select * from pg_catalog.pg_database where datname = $1', [@options[:msf_db_name]]).any?
      if !is_initialized
        DatabaseStatus::NEEDS_INIT
      else
        DatabaseStatus::RUNNING
      end
    end

    def write_db_client_auth_config
      raise NotImplementedError
    end

    def self.requirements
      []
    end

    private

    def create_db_users(msf_pass, msftest_pass)
      @conn.exec("create user #{@options[:msf_db_user]} with password '#{msf_pass}'")
      @conn.exec("create user #{@options[:msftest_db_user]} with password '#{msftest_pass}'")
      @conn.exec("alter role #{@options[:msf_db_user]} createdb")
      @conn.exec("alter role #{@options[:msftest_db_user]} createdb")
      @conn.exec("alter role #{@options[:msf_db_user]} with password '#{msf_pass}'")
      @conn.exec("alter role #{@options[:msftest_db_user]} with password '#{msftest_pass}'")
      @conn.exec("CREATE DATABASE #{@options[:msf_db_name]}")
      @conn.exec("CREATE DATABASE #{@options[:msftest_db_name]}")
      @conn.finish
    end
  end
end
