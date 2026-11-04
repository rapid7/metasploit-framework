require 'open3'
require 'tmpdir'

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

    # Atomically publish credentials with restrictive permissions on both Unix and Windows.
    # @param path [String] destination file
    # @param contents [String] file contents
    # @return [void]
    def write_private_file(path, contents)
      atomic_write(path, contents)
    end

    # Migrate the database configured by msfdb, independently of ambient database settings.
    # Default schema dumps to the profile because the installation may be read-only.
    # @param config_path [String] path to the generated database configuration
    # @return [Integer] migration command exit status
    def migrate_database(config_path)
      env = {
        'MSF_DATABASE_CONFIG' => config_path,
        'SCHEMA' => ENV.fetch('SCHEMA') { File.join(File.dirname(config_path), 'schema.rb') },
        'RAILS_ENV' => 'development',
        'DATABASE_URL' => nil,
        'PRIMARY_DATABASE_URL' => nil,
        'PGHOSTADDR' => nil,
        'PGSERVICE' => nil,
        'PGSERVICEFILE' => nil,
        'PGOPTIONS' => nil
      }
      run_cmd(['bundle', 'exec', 'rake', 'db:migrate'], env: env, show_output_on_failure: true)
    end

    # @param cmd [String, Array<String>] command and arguments
    # @param env [Hash] additional environment, excluded from debug output
    # @param show_output_on_failure [Boolean] print captured output when the command fails
    # @return [Integer] exit status, or 1 when terminated by a signal
    def run_cmd(cmd, env: {}, show_output_on_failure: false)
      puts "run_cmd: #{cmd.inspect}" if @options[:debug]

      output, status = Open3.capture2e(env, *Array(cmd))
      if @options[:debug]
        puts "'#{cmd}' returned #{status.exitstatus}"
        puts output
      elsif show_output_on_failure && !status.success?
        warn output unless output.empty?
      end
      status.exitstatus || 1
    end

    protected

    def protect_directory!(path)
      unless Gem.win_platform?
        File.chmod(0o700, path)
        return
      end

      arguments = ['icacls', path, '/inheritance:r', '/grant:r', "*#{windows_sid}:(OI)(CI)F", '*S-1-5-18:(OI)(CI)F']
      raise SecurityError, 'Could not protect the private credential directory' unless run_cmd(arguments).zero?
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

    def protect_file!(path)
      arguments = ['icacls', path, '/inheritance:r', '/grant:r', "*#{windows_sid}:F", '*S-1-5-18:F']
      raise SecurityError, 'Could not protect the private credential file' unless run_cmd(arguments).zero?
    end

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
      Dir.mktmpdir('.msfdb-', File.dirname(path)) do |directory|
        protect_directory!(directory)
        temporary_path = File.join(directory, 'file')
        File.open(temporary_path, File::WRONLY | File::CREAT | File::EXCL | File::BINARY, 0o600) {}
        # Protect the file itself before moving it: Windows can otherwise apply
        # the destination directory's inherited ACL after the rename.
        protect_file!(temporary_path) if Gem.win_platform?
        File.open(temporary_path, File::WRONLY | File::BINARY) do |file|
          file.write(contents)
          file.flush
          file.fsync
        end
        File.rename(temporary_path, path)
        sync_directory(File.dirname(path)) unless Gem.win_platform?
      end
    end

    def sync_directory(path)
      File.open(path, File::RDONLY, &:fsync)
    rescue Errno::EINVAL, Errno::ENOTSUP
      # Some filesystems do not support syncing directories.
    end

  end
end
