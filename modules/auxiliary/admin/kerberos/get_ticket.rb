##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos TGT/TGS Ticket Requestor',
        'Description' => %q{
          This module requests TGT/TGS Kerberos tickets from the KDC
        },
        'Author' => [
          'Christophe De La Fuente' # MSF module
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
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
        OptString.new('DOMAIN', [ true, 'The Fully Qualified Domain Name (FQDN). Ex: mydomain.local' ]),
        OptString.new('USER', [ true, 'The domain user' ]),
        OptString.new('PASSWORD', [ false, 'The domain user password' ]),
        OptString.new(
          'NTHASH', [
            false,
            'The NT hash in hex string. Server must support RC4'
          ]
        ),
        OptString.new(
          'AESKEY', [
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

    register_advanced_options(
      [
        OptBool.new(
          'KrbUseCachedCredentials', [
            true,
            'Use credentials stored in the database for Kerberos authentication',
            true
          ]
        ),
      ]
    )
  end

  def validate_options
    if datastore['NTHASH'].present? && !datastore['NTHASH'].match(/^\h{32}$/)
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH must be a hex string of 32 characters (128 bits)')
    end

    if datastore['AESKEY'].present? && !datastore['AESKEY'].match(/^(\h{32}|\h{64})$/)
      fail_with(Msf::Exploit::Failure::BadConfig,
                'AESKEY must be a hex string of 32 characters for 128-bits AES keys or 64 characters for 256-bits AES keys')
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
      info: "Module: #{fullname}, KDC for domain #{datastore['DOMAIN']}"
    )
  rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError,
         ::EOFError => e
    msg = e.to_s
    if e.respond_to?(:error_code) &&
       e.error_code == ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
      msg << ' - Check the authentication-related options (PASSWORD, NTHASH or AESKEY)'
    end
    fail_with(Failure::Unknown, msg)
  end

  def init_authenticator(options = {})
    options.merge!({
      host: rhost,
      realm: datastore['DOMAIN'],
      username: datastore['USER'],
      framework: framework,
      framework_module: self
    })
    options[:password] = datastore['PASSWORD'] if datastore['PASSWORD'].present?
    if datastore['NTHASH'].present?
      options[:key] = [datastore['NTHASH']].pack('H*')
      options[:etype] = Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC
    end
    if datastore['AESKEY'].present?
      options[:key] = [ datastore['AESKEY'] ].pack('H*')
      options[:etype] = if options[:key].size == 32
                          Rex::Proto::Kerberos::Crypto::Encryption::AES256
                        else
                          Rex::Proto::Kerberos::Crypto::Encryption::AES128
                        end
    end

    Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(**options)
  end

  def action_get_tgt
    print_status("#{peer} - Getting TGT for #{datastore['USER']}@#{datastore['DOMAIN']}")

    authenticator = init_authenticator({ use_cached_credentials: false })
    authenticator.authenticate({ tgt_only: true })
  end

  def action_get_tgs
    options = {
      use_cached_credentials: datastore['KrbUseCachedCredentials'].nil? ? false : datastore['KrbUseCachedCredentials']
    }
    authenticator = init_authenticator(options)

    if datastore['IMPERSONATE'].present?
      print_status("#{peer} - Getting TGS impersonating #{datastore['IMPERSONATE']}@#{datastore['DOMAIN']} (SPN: #{datastore['SPN']})")
      sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_UNKNOWN,
        name_string: [datastore['USER']]
      )
      credential = authenticator.request_tgt_only(options)
      auth_options = {
        sname: sname,
        impersonate: datastore['IMPERSONATE'],
        use_cache_tgt_only: true
      }
      tgs_ticket, _tgs_auth = authenticator.s4u2self(
        credential,
        auth_options.merge(store_credential_cache: false)
      )

      auth_options[:sname] = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
        name_string: datastore['SPN'].split('/')
      )
      auth_options[:tgs_ticket] = tgs_ticket
      auth_options.delete(:store_credential_cache)
      authenticator.s4u2proxy(credential, auth_options)
    else
      print_status("#{peer} - Getting TGS for #{datastore['USER']}@#{datastore['DOMAIN']} (SPN: #{datastore['SPN']})")
      sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
        name_string: datastore['SPN'].split('/')
      )
      auth_options = {
        sname: sname,
        use_cache_tgt_only: true
      }
      authenticator.authenticate(auth_options)
    end
  end

end
