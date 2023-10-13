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

    def init(msf_pass, msftest_pass)
      puts "Creating database at #{@db}"
      Dir.mkdir(@db)
      run_cmd("initdb --auth-host=trust --auth-local=trust -E UTF8 #{@db.shellescape}")

      File.open("#{@db}/postgresql.conf", 'a') do |f|
        f.puts "port = #{@options[:db_port]}"
      end

      # Try creating a test file at {Dir.tmpdir},
      # Else fallback to creation at @{db}
      # Else fail with error.
      if test_executable_file("#{Dir.tmpdir}")
        @socket_directory = Dir.tmpdir
      elsif test_executable_file("#{@db}")
        @socket_directory = @db
      else
        print_error("Attempt to create DB socket file at Temporary Directory and `~/.msf4/db` failed. Possibly because they are mounted with NOEXEC flags. Database initialization failed.")
      end

      start

      create_db_users(msf_pass, msftest_pass)

      write_db_client_auth_config
      restart
    end

    # Creates and attempts to execute a testfile in the specified directory,
    # to determine if it is mounted with NOEXEC flags.
    def test_executable_file(path)
      begin
        file_name = File.join(path, 'msfdb_testfile')
        File.open(file_name, 'w') do |f|
          f.puts "#!/bin/bash\necho exec"
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
        end

        if @options[:delete_existing_data]
          FileUtils.rm_r(@db_conf, force: true)
        end
      else
        puts "No data at #{@db}, doing nothing"
      end
    end

    def start
      if status == DatabaseStatus::RUNNING
        puts "Database already started at #{@db}"
        return true
      end

      print "Starting database at #{@db}..."
      pg_ctl_spawn_cmd = "pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db.shellescape} -l #{@db.shellescape}/log start &"
      puts "spawn_cmd: #{pg_ctl_spawn_cmd}" if @options[:debug]
      pg_ctl_pid = Process.spawn(pg_ctl_spawn_cmd)
      Process.detach(pg_ctl_pid)
      is_database_running = retry_until_truthy(timeout: 60) do
        status == DatabaseStatus::RUNNING
      end

      if is_database_running
        puts 'success'.green.bold.to_s
        true
      else
        begin
          Process.kill(:KILL, pg_ctl_pid)
        rescue => e
          puts "Failed to kill pg_ctl_pid=#{pg_ctl_pid} - #{e.class} #{e.message}" if @options[:debug]
        end
        puts 'failed'.red.bold.to_s
        false
      end
    end

    def stop
      if status == DatabaseStatus::RUNNING
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

    def status
      if exists?
        if run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db.shellescape} status") == 0
          DatabaseStatus::RUNNING
        else
          DatabaseStatus::INACTIVE
        end
      else
        DatabaseStatus::NOT_FOUND
      end
    end

    def create_db_users(msf_pass, msftest_pass)
      puts 'Creating database users'
      run_psql("create user #{@options[:msf_db_user].shellescape} with password '#{msf_pass}'", @socket_directory)
      run_psql("create user #{@options[:msftest_db_user].shellescape} with password '#{msftest_pass}'", @socket_directory)
      run_psql("alter role #{@options[:msf_db_user].shellescape} createdb", @socket_directory)
      run_psql("alter role #{@options[:msftest_db_user].shellescape} createdb", @socket_directory)
      run_psql("alter role #{@options[:msf_db_user].shellescape} with password '#{msf_pass}'", @socket_directory)
      run_psql("alter role #{@options[:msftest_db_user].shellescape} with password '#{msftest_pass}'", @socket_directory)

      conn = PG.connect(host: @options[:db_host], dbname: 'postgres', port: @options[:db_port], user: @options[:msf_db_user], password: msf_pass)
      conn.exec("CREATE DATABASE #{@options[:msf_db_name]}")
      conn.exec("CREATE DATABASE #{@options[:msftest_db_name]}")
      conn.finish
    end

    def write_db_client_auth_config
      client_auth_config = "#{@db}/pg_hba.conf"
      super(client_auth_config)
    end

    def self.requirements
      %w[psql pg_ctl initdb createdb]
    end

    protected

    def retry_until_truthy(timeout:)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
      ending_time = start_time + timeout
      retry_count = 0
      while Process.clock_gettime(Process::CLOCK_MONOTONIC, :second) < ending_time
        result = yield
        return result if result

        retry_count += 1
        remaining_time_budget = ending_time - Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
        break if remaining_time_budget <= 0

        delay = 2**retry_count
        if delay >= remaining_time_budget
          delay = remaining_time_budget
          puts("Final attempt. Sleeping for the remaining #{delay} seconds out of total timeout #{timeout}") if @options[:debug]
        else
          puts("Sleeping for #{delay} seconds before attempting again") if @options[:debug]
        end

        sleep delay
      end

      nil
    end
  end
end
