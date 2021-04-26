require 'msfdb_helpers/db_interface'

class Standalone < DbInterface

  def initialize(options:, msf_pass:, msftest_pass:, db_conf:)
    @options = options
    @msf_pass = msf_pass
    @msftest_pass = msftest_pass
    @db_conf = db_conf
    @conn = PG.connect(host: '127.0.0.1', dbname: 'postgres', port: @options[:db_port], user: @options[:msf_db_admin_username], password: @options[:msf_db_admin_pass])
    super(options)
  end

  def init(msf_pass, msftest_pass)
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

  def delete
    @conn.exec("DROP DATABASE IF EXISTS #{@options[:msf_db_name]};")
    @conn.exec("DROP DATABASE IF EXISTS #{@options[:msftest_db_name]};")
    @conn.exec("DROP USER IF EXISTS #{@options[:msf_db_user]};")
    @conn.exec("DROP USER IF EXISTS #{@options[:msftest_db_user]};")
    if File.exist?(@db_conf)
      File.delete(@db_conf)
    end
  end

  def reinit(msf_pass, msftest_pass)
    delete
    init(msf_pass, msftest_pass)
  end

  def start
    raise NotImplementedError
  end

  def stop
    raise NotImplementedError
  end

  def restart
    raise NotImplementedError
  end

  def status
    raise NotImplementedError
  end

  def write_db_client_auth_config
    raise NotImplementedError
  end

  def self.requirements
    Array.new
  end

end
