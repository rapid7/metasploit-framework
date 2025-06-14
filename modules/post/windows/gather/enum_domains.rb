##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::NetAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Domain Enumeration',
        'Description' => %q{
          This module enumerates currently the domains a host can see and the domain
          controllers for each domain.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'mubix' ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    domains = net_server_enum(SV_TYPE_DOMAIN_ENUM)

    fail_with(Failure::Unknown, 'No domains found') if domains.blank?

    domains.each do |domain|
      print_status("Enumerating DCs for #{domain[:name]}")
      dcs = net_server_enum(SV_TYPE_DOMAIN_BAKCTRL | SV_TYPE_DOMAIN_CTRL, domain[:name])

      if dcs.count == 0
        print_error('No Domain Controllers found...')
        next
      end

      dcs.each do |dc|
        print_good("Domain Controller: #{dc[:name]}")

        report_note(
          host: session,
          type: 'domain.hostnames',
          data: { :hostnames => dc[:name] },
          update: :unique_data
        )
      end
    end
  end
end
