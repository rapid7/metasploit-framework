##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Accounts

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Local User Account SID Lookup',
        'Description' => %q{
          This module prints information about a given SID from the perspective
          of this session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'chao-mu'],
        'Platform' => [ 'win' ],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptString.new('SID', [ true, 'SID to lookup' ]),
      OptString.new('SYSTEM_NAME', [ false, 'Where to search. If undefined, first local then trusted DCs' ]),
    ])
  end

  def run
    sid = datastore['SID']
    target_system = datastore['SYSTEM_NAME']

    info = resolve_sid(sid, target_system || nil)

    fail_with(Failure::Unknown, 'Unable to resolve SID. Giving up.') if info.nil?

    sid_type = info[:type]

    fail_with(Failure::BadConfig, 'Invalid SID provided') if sid_type == :invalid

    fail_with(Failure::Unknown, 'No account found for the given SID') unless info[:mapped]

    print_status("SID Type: #{sid_type}")
    print_status("Name:     #{info[:name]}")
    print_status("Domain:   #{info[:domain]}")
  end
end
