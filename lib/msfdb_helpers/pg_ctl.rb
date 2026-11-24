require 'msfdb_helpers/managed_cluster'

module MsfdbHelpers
  # Private cluster lifecycle using the PostgreSQL server utilities.
  class PgCtl < ManagedCluster
    def delete
      if exists?
        stop

        if @options[:delete_existing_data]
          puts "Deleting all data at #{@db}"
          cleanup_socket_directory
          FileUtils.rm_rf(@db)
          complete_initialization!
        end

        if @options[:delete_existing_data]
          FileUtils.rm_r(@db_conf, force: true)
        end
      else
        puts "No data at #{@db}, doing nothing"
      end
    end

    # @return [Integer] the private cluster's lifecycle status
    def status
      return DatabaseStatus::NOT_FOUND unless exists?

      run_cmd(['pg_ctl', '-D', @db, 'status']).zero? ? DatabaseStatus::RUNNING : DatabaseStatus::INACTIVE
    end

    # @return [Array<String>] required command-line utilities
    def self.requirements
      %w[pg_ctl initdb]
    end

    protected

    def server_version
      output, result = Open3.capture2e('initdb', '--version')
      version = output[/PostgreSQL\)?\s+(\d+(?:\.\d+)?)/, 1]
      raise SecurityError, 'Could not determine the initdb PostgreSQL version' unless result.success? && version

      version
    end

    def initialize_cluster(password_file, authentication)
      checked_command!(['initdb', "--auth=#{authentication}", '--username=postgres', "--pwfile=#{password_file}", '-E', 'UTF8', @db])
    end

    def start_cluster
      log = File.join(@db, 'log')
      # A Windows background server can inherit a captured output pipe and keep
      # capture2e waiting after pg_ctl exits. PostgreSQL writes diagnostics via -l.
      pid = Process.spawn('pg_ctl', '-D', @db, '-l', log, '-w', '-t', '60', 'start', out: File::NULL, err: File::NULL)
      Process.wait2(pid).last.success?
    end

    def stop_cluster
      run_cmd(['pg_ctl', '-D', @db, '-m', 'fast', '-w', '-t', '60', 'stop']).zero?
    end

    def hba_config
      File.join(@db, 'pg_hba.conf')
    end

    def postgresql_config
      File.join(@db, 'postgresql.conf')
    end

  end
end
