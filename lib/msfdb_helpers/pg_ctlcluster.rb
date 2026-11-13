require 'msfdb_helpers/managed_cluster'

module MsfdbHelpers
  # postgresql-common lifecycle confined to a per-user configuration root.
  class PgCtlcluster < ManagedCluster
    # @param arguments [Hash] private cluster paths and msfdb options
    def initialize(**arguments)
      super
      @pg_cluster_conf_root = File.join(@localconf, '.local', 'etc', 'postgresql')
      version_file = File.join(@db, 'PG_VERSION')
      @pg_version = File.file?(version_file) ? File.read(version_file).strip : server_version
      raise SecurityError, 'Invalid private PostgreSQL version' unless @pg_version.match?(/\A(?:9\.\d+|\d{2,})\z/)
    end

    def delete
      if exists?
        stop

        if @options[:delete_existing_data]
          puts "Deleting all data at #{@db}"
          cleanup_socket_directory
          run_cmd("pg_dropcluster #{@pg_version} #{@options[:msf_db_name].shellescape}")
          FileUtils.rm_rf(@db)
          FileUtils.rm_rf("#{@localconf}/.local/etc/postgresql")
          FileUtils.rm_r(@db_conf, force: true)
          complete_initialization!
        end
      else
        puts "No data at #{@db}, doing nothing"
      end
    end

    # @return [Integer] the private cluster's lifecycle status
    def status
      return DatabaseStatus::NOT_FOUND unless exists?

      run_cmd(['pg_ctlcluster', @pg_version, cluster_name, 'status']).zero? ? DatabaseStatus::RUNNING : DatabaseStatus::INACTIVE
    end

    # @return [Array<String>] required command-line utilities
    def self.requirements
      %w[pg_ctlcluster pg_dropcluster pg_createcluster pg_config]
    end

    # @param cmd [String, Array<String>] command and arguments
    # @param env [Hash] additional environment variables
    # @param show_output_on_failure [Boolean] print captured output when the command fails
    # @return [Integer] process exit status
    def run_cmd(cmd, env: {}, show_output_on_failure: false)
      super(cmd, env: env.merge('PG_CLUSTER_CONF_ROOT' => @pg_cluster_conf_root), show_output_on_failure: show_output_on_failure)
    end

    protected

    def postgres_binary
      output, result = Open3.capture2e('pg_config', '--bindir')
      raise SecurityError, 'Could not locate the PostgreSQL server utilities' unless result.success?

      # pg_config can point to a newer installed version than this existing cluster.
      File.join(File.dirname(File.dirname(output.strip)), @pg_version, 'bin', 'postgres')
    end

    def validate_security_target!
      super
      path = File.join(cluster_config_directory, 'pg_ctl.conf')
      return unless File.file?(path)

      custom_options = File.readlines(path).any? do |line|
        !line.strip.empty? && !line.lstrip.start_with?('#') && !line.match?(/\A\s*pg_ctl_options\s*=\s*(?:''|"")\s*(?:#.*)?\z/)
      end
      raise SecurityError, 'Custom pg_ctl startup options require manual authentication configuration review' if custom_options
    end

    def server_version
      output, result = Open3.capture2e('pg_config', '--version')
      version = output[/PostgreSQL\s+(9\.\d+|\d{2,})/, 1]
      raise SecurityError, 'Could not determine the PostgreSQL server version' unless result.success? && version

      version
    end

    def initialize_cluster(password_file, authentication)
      FileUtils.mkdir_p(@pg_cluster_conf_root, mode: 0o700)
      checked_command!([
        'pg_createcluster', '--user', Etc.getpwuid(Process.uid).name,
        '-l', File.join(@db, 'log'), '-d', @db, '-s', @db, '--encoding=UTF8',
        @pg_version, cluster_name, '--', '--username=postgres',
        "--auth=#{authentication}", "--pwfile=#{password_file}"
      ])
    end

    def start_cluster
      [0, 2].include?(run_cmd(['pg_ctlcluster', @pg_version, cluster_name, 'start', '--', '-w', '-t', '60']))
    end

    def stop_cluster
      run_cmd(['pg_ctlcluster', '-m', 'fast', @pg_version, cluster_name, 'stop', '--', '-w', '-t', '60']).zero?
    end

    def cluster_config_directory
      File.join(@pg_cluster_conf_root, @pg_version, cluster_name)
    end

    def cluster_name
      name = @options[:msf_db_name]
      unless name.is_a?(String) && !name.empty? && !%w[. ..].include?(name) && !name.match?(%r{[/\\\x00-\x1f]})
        raise SecurityError, 'The private PostgreSQL cluster name must be one directory component'
      end

      name
    end

    def hba_config
      File.join(cluster_config_directory, 'pg_hba.conf')
    end

    def postgresql_config
      File.join(cluster_config_directory, 'postgresql.conf')
    end

  end
end
