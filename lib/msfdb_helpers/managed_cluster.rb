# frozen_string_literal: true

require 'etc'
require 'digest'
require 'fileutils'
require 'json'
require 'pg'
require 'securerandom'
require 'shellwords'
require 'tmpdir'
require 'msfdb_helpers/db_interface'

module MsfdbHelpers
  # Security and lifecycle policy for private, per-user clusters only. Distro
  # database-management scripts and Standalone deliberately do not inherit this.
  class ManagedCluster < DbInterface
    LEGACY_TRUST_RULES = [
      %r{\Ahost\s+"template1"\s+all\s+127\.0\.0\.1/32\s+trust\s*(?:#.*)?\z},
      /\Alocal\s+all\s+all\s+trust\s*(?:#.*)?\z/,
      %r{\Ahost\s+all\s+all\s+(?:127\.0\.0\.1/32|::1/128)\s+trust\s*(?:#.*)?\z}
    ].freeze
    INITIALIZATION_OPTIONS = %i[msf_db_name msf_db_user msftest_db_name msftest_db_user db_host db_port db_pool].freeze
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
    #   An existing initialization checkpoint supplies the original passwords.
    # @return [Boolean] whether initialization completed
    def init(msf_pass, msftest_pass)
      state = if pending_initialization?
                initialization_state
              else
                prepare_initialization!(msf_pass, msftest_pass)
              end
      restore_initialization_options!(state)
      authentication = state.fetch('authentication')
      check_client_authentication!(authentication)
      password = state.fetch('bootstrap_password')
      initialized = false
      start_attempted = false
      begin
        if state['stage'] == 'creating'
          initialize_or_resume_cluster!(password, authentication)
          update_initialization_stage!(state, 'configuring')
        end

        if state['stage'] == 'configuring'
          configure_server!(authentication: authentication)
          write_db_client_auth_config(hba_config, authentication: authentication, bootstrap: true)
          update_initialization_stage!(state, 'bootstrap')
        end

        if state['stage'] == 'bootstrap'
          ensure_socket_directory! unless Gem.win_platform?
          start_attempted = true # rubocop:disable Lint/UselessAssignment -- The ensure block uses this if startup or bootstrap raises.
          unless status == DatabaseStatus::RUNNING || start_cluster
            raise SecurityError, 'Could not start the password-protected bootstrap database'
          end

          create_database_users!(password, state.fetch('msf_password'), state.fetch('msftest_password'))
          stop!
          start_attempted = false
          update_initialization_stage!(state, 'finalizing')
        end

        if state['stage'] == 'finalizing'
          stop!
          write_db_client_auth_config(hba_config, authentication: authentication)
          update_initialization_stage!(state, 'ready')
        end

        start_attempted = true
        ensure_socket_directory! unless Gem.win_platform?
        raise SecurityError, 'Could not start the secured database' unless status == DatabaseStatus::RUNNING || start_cluster

        verify_connections!(initialization_connections(state))
        initialized = true
        true
      ensure
        password.clear if password && !password.frozen?
        stop! if start_attempted && !initialized
      end
    end

    # @return [Boolean] whether an initialization checkpoint exists
    def pending_initialization?
      File.exist?(initialization_file) || File.symlink?(initialization_file)
    end

    # Keep credential publication and schema migration in the same initialization attempt.
    # @yield performs initialization while the per-profile lock is held
    # @return [Object] the block result
    def with_initialization_lock
      FileUtils.mkdir_p(@localconf, mode: 0o700)
      path = File.join(@localconf, '.msfdb-initialization.lock')
      raise SecurityError, 'The initialization lock must not be a symbolic link' if File.symlink?(path)

      flags = File::RDWR | File::CREAT
      flags |= File::NOFOLLOW unless Gem.win_platform?
      File.open(path, flags, 0o600) do |file|
        unless file.flock(File::LOCK_EX | File::LOCK_NB)
          raise SecurityError, 'Another database initialization is running; wait for it to finish before retrying'
        end

        yield
      ensure
        file.flock(File::LOCK_UN)
      end
    end

    # Restore the original credentials and options for a pending initialization.
    # @return [Hash] application and test passwords
    def initialization_credentials
      state = initialization_state
      restore_initialization_options!(state)
      { msf_password: state.fetch('msf_password'), msftest_password: state.fetch('msftest_password') }
    end

    # Remove the checkpoint only after credentials and schema have been published.
    # @return [void]
    def complete_initialization!
      File.delete(initialization_file) if pending_initialization?
    end

    # Remove an empty private socket directory belonging to this cluster.
    # @return [void]
    def cleanup_socket_directory
      return if Gem.win_platform? || !File.file?(socket_directory_file)

      directory = File.read(socket_directory_file)
      return if directory == @db
      raise SecurityError, 'The saved socket directory does not match this database' unless directory == socket_directory

      stat = File.lstat(directory)
      unless stat.directory? && stat.uid == Process.uid && (stat.mode & 0o077).zero?
        raise SecurityError, "Private socket directory #{directory} is not owned and restricted to the current user"
      end

      Dir.rmdir(directory)
    rescue Errno::ENOENT
      nil
    rescue Errno::ENOTEMPTY, Errno::EACCES => e
      warn "Could not remove the private socket directory: #{e.message}"
    end

    # @return [Boolean] whether the private database is running
    def start
      if pending_initialization?
        raise SecurityError, 'Database initialization is incomplete; run msfdb --component database init to resume it'
      end

      warn_insecure_authentication
      ensure_socket_directory! if File.file?(socket_directory_file)
      status == DatabaseStatus::RUNNING || start_cluster
    end

    # Warn when a managed cluster still allows passwordless connections.
    # @return [Boolean] whether trust authentication is present
    def warn_insecure_authentication
      return false unless exists? && File.file?(hba_config)

      lines = File.readlines(hba_config)
      if lines.any? { |line| authentication_include?(line) }
        warn 'Warning: This database includes additional authentication files that require manual security review.'
      end
      return false unless lines.any? { |line| trust_rule?(line) }

      warn 'Warning: This database permits passwordless access. Run msfdb --component database secure to remove the original msfdb trust rules.'
      true
    end

    # Remove only authentication rules generated by older versions of msfdb, while stopped.
    # @return [Boolean] whether the authentication file is secured
    def secure
      raise SecurityError, 'Resume the incomplete initialization before securing this database' if pending_initialization?
      raise SecurityError, 'No private database cluster exists' unless exists? && File.file?(hba_config)

      require_stopped!
      validate_security_target!
      lines = File.readlines(hba_config)
      if lines.any? { |line| authentication_include?(line) }
        raise SecurityError, 'The authentication file includes other files; review the complete configuration manually'
      end
      if lines.any? { |line| line.rstrip.end_with?('\\') }
        raise SecurityError, 'Continued authentication rules require manual configuration review'
      end

      trust_lines = lines.select { |line| trust_rule?(line) }
      if trust_lines.any? { |line| LEGACY_TRUST_RULES.none? { |pattern| pattern.match?(line.strip) } }
        raise SecurityError, 'The authentication file contains custom trust rules; review them manually before securing this cluster'
      end

      require_stopped!
      if trust_lines.empty?
        puts 'The private database authentication file has no trust rules; PostgreSQL remains stopped'
        return true
      end

      backup_path = "#{hba_config}.msfdb-#{SecureRandom.hex(6)}.bak"
      atomic_write(backup_path, lines.join)
      backup = backup_path
      puts "Authentication configuration backup: #{backup}"
      secured = lines.reject { |line| LEGACY_TRUST_RULES.any? { |pattern| pattern.match?(line.strip) } }.join
      atomic_write(hba_config, secured)

      puts 'Removed legacy passwordless authentication rules without changing database contents; PostgreSQL remains stopped'
      true
    rescue SecurityError, SystemCallError => e
      raise SecurityError, "#{e.message}. Authentication backup: #{backup}" if backup
      raise SecurityError, "Could not complete the authentication backup; database configuration was not changed: #{e.message}" if backup_path

      raise
    end

    # @return [Boolean] whether the private database was restarted
    # @raise [SecurityError] if shutdown or startup fails
    def restart
      stop
      raise SecurityError, 'Database restart failed; inspect the private database log' unless start

      true
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

    def require_stopped!
      raise SecurityError, 'The database is running and remains unchanged. Run msfdb --component database stop before secure' if status == DatabaseStatus::RUNNING
    end

    def validate_security_target!
      unless File.basename(@db) == 'db' && File.realpath(File.dirname(@db)) == File.realpath(@localconf)
        raise SecurityError, 'Custom database layouts require manual authentication configuration review'
      end

      [@db, hba_config].each do |path|
        stat = File.lstat(path)
        if stat.symlink? || (!Gem.win_platform? && stat.uid != Process.uid)
          raise SecurityError, 'The private database configuration must belong to the current account without symbolic links'
        end
      end
      unless File.realpath(configuration_setting('data_directory')) == File.realpath(@db) &&
             File.realpath(configuration_setting('hba_file')) == File.realpath(hba_config)
        raise SecurityError, 'PostgreSQL uses a different data or authentication configuration; review it manually'
      end
    rescue SystemCallError => e
      raise SecurityError, "Could not verify the private PostgreSQL configuration: #{e.message}"
    end

    def postgres_binary
      'postgres'
    end

    def configuration_setting(setting)
      # PostgreSQL permits administrators to inspect settings only with -C first.
      output, _error, result = Open3.capture3(postgres_binary, '-C', setting, '-D', @db, '-c', "config_file=#{postgresql_config}")
      raise SecurityError, 'Could not inspect the effective PostgreSQL configuration; review it manually' unless result.success?

      output.strip
    end

    def initialization_file
      File.join(@localconf, '.msfdb-initialization.json')
    end

    def prepare_initialization!(msf_pass, msftest_pass)
      raise SecurityError, 'A database directory already exists; use start without reinitializing it' if exists?
      if File.exist?(@db_conf) || File.symlink?(@db_conf)
        raise SecurityError, 'Existing database.yml without a private cluster requires manual review; credentials have not been overwritten'
      end

      authentication = server_version.split('.').first.to_i >= 10 ? 'scram-sha-256' : 'md5'
      check_client_authentication!(authentication)
      validate_application_names!(authentication)
      FileUtils.mkdir_p(@localconf, mode: 0o700)
      state = {
        'version' => 1, 'stage' => 'creating', 'db_path' => @db, 'db_conf' => @db_conf,
        'authentication' => authentication, 'bootstrap_password' => SecureRandom.hex(32),
        'msf_password' => msf_pass, 'msftest_password' => msftest_pass,
        'options' => INITIALIZATION_OPTIONS.to_h { |key| [key.to_s, @options[key]] }
      }
      atomic_write(initialization_file, JSON.generate(state))
      state
    end

    def validate_application_names!(authentication)
      authentication_config(authentication: authentication)
      roles = [@options[:msf_db_user], @options[:msftest_db_user]]
      databases = [@options[:msf_db_name], @options[:msftest_db_name]]
      if (roles + databases).any? { |name| !name.is_a?(String) } || roles.uniq.length != 2 || roles.include?('postgres') ||
         databases.uniq.length != 2 || (databases & %w[postgres template0 template1]).any?
        raise SecurityError, 'Application roles and databases must be distinct from each other and PostgreSQL system names'
      end
    rescue ArgumentError => e
      raise SecurityError, "Invalid private database name or role: #{e.message}"
    end

    def check_client_authentication!(authentication)
      if authentication == 'scram-sha-256' && PG.library_version < 100_000
        raise SecurityError, 'PostgreSQL 10 or later requires a libpq client with SCRAM support; upgrade libpq and the pg gem before initializing'
      end
    end

    def initialization_state
      stat = File.lstat(initialization_file)
      if !stat.file? || stat.symlink? || (!Gem.win_platform? && (stat.uid != Process.uid || (stat.mode & 0o077) != 0))
        raise SecurityError, 'The initialization checkpoint is not a private file owned by the current user'
      end

      state = JSON.parse(File.read(initialization_file))
      unless state.is_a?(Hash) && state['version'] == 1 && state['db_path'] == @db && state['db_conf'] == @db_conf &&
             %w[creating configuring bootstrap finalizing ready].include?(state['stage']) &&
             %w[md5 scram-sha-256].include?(state['authentication']) && state['options'].is_a?(Hash) &&
             %w[bootstrap_password msf_password msftest_password].all? { |key| state[key].is_a?(String) && !state[key].empty? } &&
             INITIALIZATION_OPTIONS.all? { |key| state['options'].key?(key.to_s) }
        raise SecurityError, 'The initialization checkpoint is invalid; inspect it before retrying'
      end

      state
    rescue JSON::ParserError
      raise SecurityError, 'The initialization checkpoint is invalid; inspect it before retrying'
    end

    def restore_initialization_options!(state)
      INITIALIZATION_OPTIONS.each { |key| @options[key] = state.fetch('options').fetch(key.to_s) }
      validate_application_names!(state.fetch('authentication'))
    end

    def update_initialization_stage!(state, stage)
      state['stage'] = stage
      atomic_write(initialization_file, JSON.generate(state))
    end

    def initialize_or_resume_cluster!(password, authentication)
      Dir.mkdir(@db, 0o700) unless exists?
      unless Dir.empty?(@db) && !File.exist?(hba_config)
        raise SecurityError, "Database initialization was interrupted while creating #{@db}; inspect the partial cluster before retrying"
      end

      with_password_file(password) { |path| initialize_cluster(path, authentication) }
    end

    def initialization_connections(state)
      [
        [@options[:msf_db_name], @options[:msf_db_user], state.fetch('msf_password')],
        [@options[:msftest_db_name], @options[:msftest_db_user], state.fetch('msftest_password')]
      ]
    end

    def trust_rule?(line)
      quoted = false
      line.each_char.with_index do |character, index|
        quoted = !quoted if character == '"'
        if character == '#' && !quoted
          line = line[0...index]
          break
        end
      end
      # Authentication options follow the method as name=value fields. Keep
      # quoted values together, then dequote partially quoted method names.
      fields = line.scan(/(?:[^\s",]+|"[^"]*")+/)
      method = fields.reverse.find { |field| !field.include?('=') }
      method.to_s.delete('"') == 'trust'
    end

    def authentication_include?(line)
      # PostgreSQL dequotes the first field before recognizing include directives.
      directive = line.split.first.to_s.delete('"')
      %w[include include_if_exists include_dir].include?(directive)
    end

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
        directory = ensure_socket_directory!
        contents << "unix_socket_directories = #{postgresql_literal(directory)}\nunix_socket_permissions = 0700\n"
        atomic_write(socket_directory_file, directory)
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

    def socket_directory_file
      File.join(@db, '.msfdb-socket-directory')
    end

    def socket_directory
      # Leave room for the socket filename and the shorter sockaddr_un limit on macOS.
      # postgresql-common does not parse quoted directory lists and uses the
      # directory in a shell command, so use a simple path for those characters.
      return @db if "#{@db}/.s.PGSQL.#{@options[:db_port]}".bytesize <= 90 && !@db.match?(%r{[^a-zA-Z0-9_./-]})

      File.join('/tmp', "msfdb-#{Process.uid}-#{Digest::SHA256.hexdigest(@db)[0, 16]}")
    end

    def ensure_socket_directory!
      directory = socket_directory
      return directory if directory == @db

      begin
        Dir.mkdir(directory, 0o700)
      rescue Errno::EEXIST
        # A persistent directory is reused after a restart or after /tmp is cleaned.
      end
      stat = File.lstat(directory)
      unless stat.directory? && stat.uid == Process.uid && (stat.mode & 0o077).zero?
        raise SecurityError, "Private socket directory #{directory} is not owned and restricted to the current user"
      end

      directory
    end

    def create_database_users!(password, msf_pass, msftest_pass)
      # An explicit empty hostaddr prevents PGHOSTADDR from overriding the socket.
      bootstrap = {
        host: socket_directory,
        hostaddr: '',
        port: @options[:db_port],
        user: 'postgres',
        password: password,
        connect_timeout: 5
      }
      bootstrap.merge!(host: '127.0.0.1', hostaddr: '127.0.0.1') if Gem.win_platform?
      PG.connect(**bootstrap, dbname: 'postgres') do |connection|
        [[@options[:msf_db_user], msf_pass], [@options[:msftest_db_user], msftest_pass]].each do |user, secret|
          role = connection.quote_ident(user)
          exists = connection.exec_params('SELECT 1 FROM pg_roles WHERE rolname = $1', [user]).any?
          operation = exists ? 'ALTER' : 'CREATE'
          connection.exec("#{operation} ROLE #{role} LOGIN NOSUPERUSER NOCREATEROLE CREATEDB PASSWORD #{connection.escape_literal(secret)}")
        end
        [@options[:msf_db_name], @options[:msftest_db_name]].each do |database|
          result = connection.exec_params('SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = $1', [database])
          if result.any?
            unless result.getvalue(0, 0) == @options[:msf_db_user]
              raise SecurityError, 'An existing initialization database has an unexpected owner; inspect the partial cluster'
            end
          else
            connection.exec("CREATE DATABASE #{connection.quote_ident(database)} OWNER #{connection.quote_ident(@options[:msf_db_user])}")
          end
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
