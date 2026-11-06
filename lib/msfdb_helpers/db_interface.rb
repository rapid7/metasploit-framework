require 'open3'
require 'tempfile'

module MsfdbHelpers
  class SecurityError < StandardError; end

  # Common command execution and password-only authentication configuration.
  class DbInterface
    AUTH_CONFIG_HEADER = '# msfdb authentication v1'.freeze

    def initialize(options)
      @options = options
    end

    def init
      raise NotImplementedError
    end

    def delete
      raise NotImplementedError
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

    # @param client_auth_config [String] the cluster's authentication file
    # @param authentication [String] the password authentication method
    # @param bootstrap [Boolean] whether to allow only the temporary bootstrap role
    # @return [void]
    def write_db_client_auth_config(client_auth_config, authentication: 'md5', bootstrap: false)
      puts "Writing client authentication configuration file #{client_auth_config}"
      atomic_write(client_auth_config, authentication_config(authentication: authentication, bootstrap: bootstrap))
    end

    # @param authentication [String] the password authentication method
    # @param bootstrap [Boolean] whether to allow only the temporary bootstrap role
    # @return [String] the complete authentication configuration
    def authentication_config(authentication: 'md5', bootstrap: false)
      unless %w[md5 scram-sha-256].include?(authentication)
        raise ArgumentError, 'Unsupported password authentication method'
      end

      pairs = if bootstrap
                [['all', 'postgres']]
              else
                [
                  [@options[:msf_db_name], @options[:msf_db_user]],
                  [@options[:msftest_db_name], @options[:msftest_db_user]],
                  ['postgres', @options[:msftest_db_user]]
                ]
              end
      rules = [AUTH_CONFIG_HEADER]
      pairs.each do |database, user|
        database = bootstrap ? 'all' : hba_identifier(database)
        user = hba_identifier(user)
        rules << "local #{database} #{user} #{authentication}" unless Gem.win_platform?
        %w[127.0.0.1/32 ::1/128].each do |address|
          rules << "host #{database} #{user} #{address} #{authentication}"
        end
      end
      rules.join("\n") + "\n"
    end

    def self.requirements
      []
    end

    # @param cmd [String, Array<String>] command and arguments
    # @param env [Hash] additional environment, excluded from debug output
    # @return [Integer] exit status, or 1 when terminated by a signal
    def run_cmd(cmd, env: {})
      puts "run_cmd: #{cmd.inspect}" if @options[:debug]

      output, status = Open3.capture2e(env, *Array(cmd))
      if @options[:debug]
        puts "'#{cmd}' returned #{status.exitstatus}"
        puts output
      end
      status.exitstatus || 1
    end

    protected

    def hba_identifier(value)
      value = value.to_s
      # PostgreSQL treats a leading slash as a regular expression even when quoted.
      if value.empty? || value.start_with?('/') || value.match?(/[\r\n\x00]/)
        raise ArgumentError, 'Database names and roles must be nonempty single-line identifiers without a leading slash'
      end
      # HBA names must match PostgreSQL's default 63-byte identifiers without truncation.
      raise ArgumentError, 'Database names and roles must be at most 63 bytes' if value.bytesize > 63

      '"' + value.gsub('"', '""') + '"'
    end

    def atomic_write(path, contents)
      Tempfile.create(['.msfdb-', '.conf'], File.dirname(path)) do |file|
        file.chmod(0o600)
        file.write(contents)
        file.flush
        file.fsync
        file.close
        File.rename(file.path, path)
      end
    end

  end
end
