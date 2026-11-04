# frozen_string_literal: true

require 'etc'
require 'fileutils'
require 'pg'
require 'securerandom'
require 'shellwords'
require 'tmpdir'
require 'msfdb_helpers/db_interface'

module MsfdbHelpers
  # Security and lifecycle policy for private, per-user clusters only. Distro
  # database-management scripts and Standalone deliberately do not inherit this.
  class ManagedCluster < DbInterface
    # @param db_path [String] the private cluster's data directory
    # @param options [Hash] msfdb options
    # @param localconf [String] the owning user's configuration directory
    # @param db_conf [String] the generated application credentials file
    def initialize(db_path:, options:, localconf:, db_conf:)
      super(options)
      @db = File.expand_path(db_path)
      @localconf = File.expand_path(localconf)
      @db_conf = File.expand_path(db_conf)
    end

    # @param msf_pass [String] the application password
    # @param msftest_pass [String] the test application password
    # @return [Boolean] whether initialization completed
    def init(msf_pass, msftest_pass)
      raise SecurityError, 'A database directory already exists; use start without reinitializing it' if exists?
      if File.exist?(@db_conf) || File.symlink?(@db_conf)
        raise SecurityError, 'Existing database.yml without a private cluster requires manual review; credentials have not been overwritten'
      end

      FileUtils.mkdir_p(@localconf, mode: 0o700)
      authentication = server_version.split('.').first.to_i >= 10 ? 'scram-sha-256' : 'md5'
      # Validate identifiers before creating cluster files or a bootstrap secret.
      authentication_config(authentication: authentication)
      password = SecureRandom.hex(32)
      Dir.mkdir(@db, 0o700)
      initialized = false
      start_attempted = false
      begin
        with_password_file(password) { |path| initialize_cluster(path, authentication) }
        configure_server!(authentication: authentication)
        write_db_client_auth_config(hba_config, authentication: authentication, bootstrap: true)
        # A failing startup command can still leave a server running.
        start_attempted = true
        raise SecurityError, 'Could not start the password-protected bootstrap database' unless start_cluster

        create_database_users!(password, msf_pass, msftest_pass)
        stop!
        start_attempted = false
        write_db_client_auth_config(hba_config, authentication: authentication)
        start_attempted = true
        raise SecurityError, 'Could not start the secured database' unless start_cluster

        verify_connections!([
          [@options[:msf_db_name], @options[:msf_db_user], msf_pass],
          [@options[:msftest_db_name], @options[:msftest_db_user], msftest_pass]
        ])
        initialized = true
        true
      ensure
        password.clear
        stop! if start_attempted && !initialized
      end
    end

    # @return [Boolean] whether the private database is running
    def start
      status == DatabaseStatus::RUNNING || start_cluster
    end

    # @return [Boolean] whether the private database was restarted
    def restart
      stop
      start
    end

    # @return [Boolean] whether the private database stopped
    def stop
      stop!
      true
    end

    # @return [Boolean] whether the private data directory exists
    def exists?
      File.exist?(@db) || File.symlink?(@db)
    end

    # @param client_auth_config [String] the cluster authentication file
    # @option options [String] :authentication password authentication method
    # @option options [Boolean] :bootstrap whether this is bootstrap configuration
    # @return [void]
    def write_db_client_auth_config(client_auth_config = hba_config, **)
      super(client_auth_config, **)
    end

    protected

    def configure_server!(authentication:)
      File.chmod(0o700, @db) unless Gem.win_platform?
      keys = %w[port unix_socket_directories unix_socket_permissions listen_addresses password_encryption]
      contents = File.readlines(postgresql_config).reject do |line|
        line.match?(/\A\s*(?:#{keys.join('|')})\s*=/)
      end.join
      contents << "\n# Private msfdb connection settings\nport = #{@options[:db_port]}\n"
      # localhost can fall back to IPv6 when another account owns the IPv4 port.
      contents << "listen_addresses = '127.0.0.1'\n"
      contents << "password_encryption = 'scram-sha-256'\n" if authentication == 'scram-sha-256'
      unless Gem.win_platform?
        contents << "unix_socket_directories = #{postgresql_literal(@db)}\nunix_socket_permissions = 0700\n"
      end
      atomic_write(postgresql_config, contents)
    end

    def postgresql_literal(value)
      "'#{value.gsub(/[\\']/) { |character| character == "'" ? "''" : '\\\\' }}'"
    end

    def with_password_file(password)
      Dir.mktmpdir('.msfdb-bootstrap-', @localconf) do |directory|
        protect_directory!(directory)
        path = File.join(directory, 'password')
        File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(password) }
        yield path
      end
    end

    def protect_directory!(path)
      unless Gem.win_platform?
        File.chmod(0o700, path)
        return
      end
      checked_command!(['icacls', path, '/inheritance:r', '/grant:r', "*#{windows_sid}:(OI)(CI)F", '*S-1-5-18:(OI)(CI)F'])
    end

    def windows_sid
      @windows_sid ||= begin
        script = "$ErrorActionPreference = 'Stop'; [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
        output, _error, result = Open3.capture3('powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script)
        sid = output.strip
        unless result.success? && sid.match?(/\AS-\d+(?:-\d+)+\z/)
          raise SecurityError, 'Could not identify the Windows account for private database ACLs'
        end

        sid
      end
    end

    def create_database_users!(password, msf_pass, msftest_pass)
      # An explicit empty hostaddr prevents PGHOSTADDR from overriding the socket.
      bootstrap = {
        host: @db,
        hostaddr: '',
        port: @options[:db_port],
        user: 'postgres',
        password: password,
        connect_timeout: 5
      }
      bootstrap.merge!(host: '127.0.0.1', hostaddr: '127.0.0.1') if Gem.win_platform?
      PG.connect(**bootstrap, dbname: 'postgres') do |connection|
        [[@options[:msf_db_user], msf_pass], [@options[:msftest_db_user], msftest_pass]].each do |user, secret|
          connection.exec("CREATE ROLE #{connection.quote_ident(user)} LOGIN NOSUPERUSER NOCREATEROLE CREATEDB PASSWORD #{connection.escape_literal(secret)}")
        end
        [@options[:msf_db_name], @options[:msftest_db_name]].each do |database|
          connection.exec("CREATE DATABASE #{connection.quote_ident(database)} OWNER #{connection.quote_ident(@options[:msf_db_user])}")
        end
      end
      # PostgreSQL 15+ no longer grants public schema creation to PUBLIC. Keep
      # the existing database ownership while allowing the test role to migrate.
      PG.connect(**bootstrap, dbname: @options[:msftest_db_name]) do |connection|
        connection.exec("GRANT ALL ON SCHEMA public TO #{connection.quote_ident(@options[:msftest_db_user])}")
      end
    rescue PG::Error
      raise SecurityError, 'Could not create private database roles/databases with authenticated bootstrap credentials'
    end

    def verify_connections!(credentials)
      credentials.each do |database, user, password|
        PG.connect(host: '127.0.0.1', hostaddr: '127.0.0.1', port: @options[:db_port], dbname: database, user: user,
                   password: password, connect_timeout: 5) do |connection|
          unless connection.exec('SELECT rolsuper FROM pg_roles WHERE rolname = current_user').getvalue(0, 0) == 'f'
            raise SecurityError, 'An application role is a database superuser; review its privileges manually'
          end
        end
      end
    rescue PG::Error
      raise SecurityError, 'Private database application authentication failed; credentials and authentication configuration were preserved'
    end

    def stop!
      return unless status == DatabaseStatus::RUNNING

      unless stop_cluster && status != DatabaseStatus::RUNNING
        raise SecurityError, 'Could not stop the private cluster; inspect its status and log'
      end
    end

    def checked_command!(arguments)
      raise SecurityError, "PostgreSQL setup command failed: #{arguments.first}" unless run_cmd(arguments).zero?
    end
  end
end
