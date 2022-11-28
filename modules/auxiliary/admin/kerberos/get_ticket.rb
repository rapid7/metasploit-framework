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
  end

  def action_get_tgt
    ticket_options = Rex::Proto::Kerberos::Model::KdcOptionFlags.from_flags(
      [
        Rex::Proto::Kerberos::Model::KdcOptionFlag::FORWARDABLE,
        Rex::Proto::Kerberos::Model::KdcOptionFlag::RENEWABLE,
        Rex::Proto::Kerberos::Model::KdcOptionFlag::CANONICALIZE,
        Rex::Proto::Kerberos::Model::KdcOptionFlag::RENEWABLE_OK
      ]
    )
    options = {
      realm: datastore['DOMAIN'],
      server_name: "krbtgt/#{datastore['DOMAIN']}",
      client_name: datastore['USER'],
      options: ticket_options
    }
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

    tgt_result = send_request_tgt(options)
    print_good("#{peer} - Received a valid TGT-Response")

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'kerberos',
      info: "Module: #{fullname}, KDC for domain #{options[:realm]}"
    )

    cache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.from_responses(
      tgt_result.as_rep,
      tgt_result.decrypted_part
    )
    path = store_loot(
      'mit.kerberos.ccache',
      'application/octet-stream',
      rhost,
      cache.encode,
      nil,
      loot_info(options)
    )
    print_status("#{peer} - TGT MIT Credential Cache saved on #{path}")

    cache.credentials.first
  rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError,
         ::EOFError => e
    msg = e.to_s
    if e.respond_to?(:error_code) &&
       e.error_code == ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
      msg << ' - Check the authentication-related options (PASSWORD, NTHASH or AESKEY)'
    end
    fail_with(Failure::Unknown, "Error while requesting a TGT: #{e}")
  end

  def action_get_tgs
    credential = nil
    options = {
      realm: datastore['DOMAIN'],
      client_name: datastore['USER']
    }

    if datastore['KrbUseCachedCredentials']
      # load a cached TGT
      options[:server_name] = "krbtgt/#{datastore['DOMAIN']}"
      credential = get_cached_credential(options)
    end

    if credential
      print_status("#{peer} - Using cached credential for #{credential.server} #{credential.client}")
    else
      credential = action_get_tgt
    end

    begin
      options[:server_name] = datastore['SPN']
      request_tgs_from_tgt(credential, options)
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError,
           ::EOFError => e
      fail_with(Failure::Unknown, "Error while requesting a TGS: #{e}")
    end
  end

  def loot_info(options = {})
    info = []

    info << "realm: #{options[:realm].upcase}" if options[:realm]
    info << "serviceName: #{options[:server_name].downcase}" if options[:server_name]
    info << "username: #{options[:client_name].downcase}" if options[:client_name]

    info.join(', ')
  end

  def get_cached_credential(options = {})
    return nil unless active_db?

    now = Time.now.utc
    host = report_host(workspace: myworkspace, host: rhost)
    framework.db.loot(
      workspace: myworkspace,
      host: host,
      ltype: 'mit.kerberos.ccache',
      info: loot_info(options)
    ).each do |stored_loot|
      ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(stored_loot.data)
      # at this time Metasploit stores 1 credential per ccache file, so no need to iterate through them
      credential = ccache.credentials.first

      tkt_start = if credential.starttime == Time.at(0).utc
                    credential.authtime
                  else
                    credential.starttime
                  end
      tkt_end = credential.endtime
      return credential if tkt_start < now && now < tkt_end
    end

    nil
  end

  def request_tgs_from_tgt(credential, options)
    now = Time.now.utc
    expiry_time = now + 1.day

    ticket = Rex::Proto::Kerberos::Model::Ticket.decode(credential.ticket.value)
    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: credential.keyblock.enctype.value,
      value: credential.keyblock.data.value
    )
    ticket_options = Rex::Proto::Kerberos::Model::KdcOptionFlags.from_flags(
      [
        Rex::Proto::Kerberos::Model::KdcOptionFlag::FORWARDABLE,
        Rex::Proto::Kerberos::Model::KdcOptionFlag::RENEWABLE,
        Rex::Proto::Kerberos::Model::KdcOptionFlag::CANONICALIZE,
      ]
    )

    tgs_res = send_request_tgs(
      req: build_tgs_request(
        {
          session_key: session_key,
          subkey: nil,
          checksum: nil,
          ticket: ticket,
          realm: options[:realm],
          client_name: options[:client_name],
          options: ticket_options,

          body: build_tgs_request_body(
            cname: nil,
            server_name: options[:server_name],
            server_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
            realm: options[:realm],
            etype: [ticket.enc_part.etype],
            options: ticket_options,

            # Specify nil to ensure the KDC uses the current time for the desired starttime of the requested ticket
            from: nil,
            till: expiry_time,
            rtime: nil,

            # certificate time
            ctime: now
          )
        }
      )
    )

    if tgs_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      raise ::Rex::Proto::Kerberos::Model::Error::KerberosError.new(res: tgs_res)
    end

    print_good("#{peer} - Received a valid TGS-Response")

    cache = extract_kerb_creds(
      tgs_res,
      session_key.value,
      msg_type: Rex::Proto::Kerberos::Crypto::KeyUsage::TGS_REP_ENCPART_SESSION_KEY
    )
    path = store_loot(
      'mit.kerberos.ccache',
      'application/octet-stream',
      rhost,
      cache.encode,
      nil,
      loot_info(options)
    )
    print_status("#{peer} - TGS MIT Credential Cache saved to #{path}")
  end

end
