require 'msfdb_helpers/db_interface'

module MsfdbHelpers
  class PgCtl < DbInterface

    def initialize(db_path:, options:, localconf:, db_conf:)
      @db = db_path
      @options = options
      @localconf = localconf
      @db_conf = db_conf
      @socket_directory = db_path
      super(options)
    end

    # @param msf_pass [String] password for the primary database user
    # @param msftest_pass [String] password for the test database user
    # @yield persist connection configuration before provisioning an owned cluster
    # @return [Boolean] whether the database was configured successfully
    # @raise [PG::ConnectionBad] if cluster initialization or startup fails
    # @raise [PG::Error] if user or database provisioning fails
    def init(msf_pass, msftest_pass)
      if initialization_pending?
        unless File.read(initialization_marker) == 'setup'
          raise PG::ConnectionBad, "PostgreSQL initialization did not finish at #{@db}; inspect the data before running msfdb reinit"
        end

        # Only clusters created by an interrupted msfdb init are resumed. Stop
        # that server before changing its socket and authentication configuration.
        if running? && stop != 0
          raise PG::ConnectionBad, "Could not stop incomplete database at #{@db}; check #{@db}/log"
        end
      else
        puts "Creating database at #{@db}"
        Dir.mkdir(@db)
        # initdb requires an empty directory, so its progress marker lives beside it.
        File.write(initialization_marker, 'initdb', mode: 'w', perm: 0o600)
        unless run_cmd("initdb --auth-host=trust --auth-local=trust --username=postgres -E UTF8 #{@db.shellescape}") == 0
          raise PG::ConnectionBad, "Could not initialize PostgreSQL at #{@db}"
        end

        File.write(initialization_marker, 'setup')
      end

      yield if block_given?

      File.open("#{@db}/postgresql.conf", 'a') do |f|
        f.puts "port = #{@options[:db_port]}"
      end

      # Try creating a test file at {Dir.tmpdir},
      # Else fallback to creation at @{db}
      # Else fail with error.
      if Gem.win_platform?
        # Windows doesn't support Unix sockets; always use TCP
        @socket_directory = @options[:db_host]
      elsif test_executable_file("#{Dir.tmpdir}")
        @socket_directory = Dir.tmpdir
      elsif test_executable_file("#{@db}")
        @socket_directory = @db
      else
        raise PG::ConnectionBad, "Could not create a database socket at #{Dir.tmpdir} or #{@db}"
      end

      # A timed-out pg_ctl can leave PostgreSQL starting in the background.
      # Install the intended authentication rules before it can accept clients.
      write_db_client_auth_config
      unless start_database
        raise PG::ConnectionBad, "PostgreSQL did not become ready at #{@db}; check #{@db}/log"
      end

      create_db_users(msf_pass, msftest_pass)
      true
    end

    # Serialize initialization, including the caller's configuration and migrations.
    # A failed attempt remains distinguishable from an existing usable database.
    # @yield initialize the database, write configuration and run migrations
    # @return [void]
    # @raise [PG::ConnectionBad] if another initializer holds the cluster lock
    def with_initialization
      File.open("#{@db}.lock", File::RDWR | File::CREAT, 0o600) do |lock|
        unless lock.flock(File::LOCK_EX | File::LOCK_NB)
          raise PG::ConnectionBad, "Database initialization already in progress at #{@db}"
        end

        yield
        File.delete(initialization_marker) if initialization_pending?
      end
    end

    # @return [Boolean] whether this cluster has an incomplete initialization marker
    def initialization_pending?
      File.file?(initialization_marker)
    end

    # Creates and attempts to execute a testfile in the specified directory,
    # to determine if it is mounted with NOEXEC flags.
    def test_executable_file(path)
      begin
        file_name = File.join(path, 'msfdb_testfile')
        File.open(file_name, 'w') do |f|
          f.puts "#!/bin/sh\necho exec"
        end
        File.chmod(0744, file_name)

        if run_cmd(file_name)
          File.open("#{@db}/postgresql.conf", 'a') do |f|
            f.puts "unix_socket_directories = \'#{path}\'"
          end
          puts "Creating db socket file at #{path}"
        end
        return true

      rescue => e
        return false

      ensure
        begin
          File.delete(file_name)
        rescue
          print_error("Unable to delete test file #{file_name}")
        end
      end

    end

    def delete
      if exists?
        stop

        if @options[:delete_existing_data]
          puts "Deleting all data at #{@db}"
          FileUtils.rm_rf(@db)
          File.delete(initialization_marker) if initialization_pending?
        end

        if @options[:delete_existing_data]
          FileUtils.rm_r(@db_conf, force: true)
        end
      else
        puts "No data at #{@db}, doing nothing"
      end
    end

    # @return [Boolean] whether PostgreSQL started successfully or was already running
    def start
      if initialization_pending?
        print_error('Database initialization is incomplete; run msfdb init before starting it')
        return false
      end

      start_database
    end

    # @return [Integer, nil] pg_ctl's exit status, or nil if the server is not running
    def stop
      if running?
        puts "Stopping database at #{@db}"
        run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db.shellescape} stop")
      else
        puts "Database is no longer running at #{@db}"
      end
    end

    def restart
      stop
      start
    end

    def exists?
      Dir.exist?(@db)
    end

    # @return [Integer] the matching DatabaseStatus constant
    def status
      return DatabaseStatus::NEEDS_INIT if initialization_pending?

      if exists?
        return DatabaseStatus::NEEDS_INIT unless File.file?(File.join(@db, 'PG_VERSION'))

        if running?
          DatabaseStatus::RUNNING
        else
          DatabaseStatus::INACTIVE
        end
      else
        DatabaseStatus::NOT_FOUND
      end
    end

    # @param msf_pass [String] password for the primary database user
    # @param msftest_pass [String] password for the test database user
    # @return [void]
    # @raise [PG::Error] if user or database provisioning fails
    def create_db_users(msf_pass, msftest_pass)
      puts 'Creating database users'
      PG.connect(host: @socket_directory, dbname: 'postgres', port: @options[:db_port], user: 'postgres') do |conn|
        [[@options[:msf_db_user], msf_pass], [@options[:msftest_db_user], msftest_pass]].each do |user, password|
          unless conn.exec_params('SELECT 1 FROM pg_roles WHERE rolname = $1', [user]).any?
            conn.exec("CREATE ROLE #{conn.quote_ident(user)}")
          end
          conn.exec("ALTER ROLE #{conn.quote_ident(user)} LOGIN CREATEDB PASSWORD #{conn.escape_literal(password)}")
        end
      end

      # Use the application role so it owns both databases, including on retry.
      PG.connect(host: @socket_directory, dbname: 'postgres', port: @options[:db_port], user: @options[:msf_db_user], password: msf_pass) do |conn|
        [@options[:msf_db_name], @options[:msftest_db_name]].each do |database|
          unless conn.exec_params('SELECT 1 FROM pg_database WHERE datname = $1', [database]).any?
            conn.exec("CREATE DATABASE #{conn.quote_ident(database)}")
          end
        end
      end
    end

    def write_db_client_auth_config
      client_auth_config = "#{@db}/pg_hba.conf"
      super(client_auth_config)
    end

    def self.requirements
      %w[psql pg_ctl initdb createdb]
    end

    private

    def start_database
      if running?
        puts "Database already started at #{@db}"
        return true
      end

      print "Starting database at #{@db}..."
      # Wait for readiness, not just a live postmaster. Avoid captured pipes:
      # PostgreSQL can inherit them on Windows and keep capture2e waiting for EOF.
      pg_ctl_spawn_cmd = ['pg_ctl', '-o', "-p #{@options[:db_port]}", '-D', @db, '-l', "#{@db}/log", '-w', '-t', '60', 'start']
      puts "spawn_cmd: #{pg_ctl_spawn_cmd.shelljoin}" if @options[:debug]
      pg_ctl_pid = Process.spawn(*pg_ctl_spawn_cmd)
      startup_status = Process.detach(pg_ctl_pid).value

      if startup_status.success?
        puts 'success'.green.bold
        true
      else
        puts 'failed'.red.bold
        false
      end
    end

    def initialization_marker
      "#{@db}.initializing"
    end

    def running?
      run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db.shellescape} status") == 0
    end

  end
end
