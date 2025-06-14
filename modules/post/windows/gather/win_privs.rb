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
        'Name' => 'Windows Gather Privileges Enumeration',
        'Description' => %q{
          This module will print if UAC is enabled, and if the current account is
          ADMIN enabled. It will also print UID, foreground SESSION ID, is SYSTEM status
          and current process PRIVILEGES.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Merlyn Cousins <drforbin6[at]gmail.com>'],
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
              stdapi_railgun_api
              stdapi_sys_config_getprivs
              stdapi_sys_config_getuid
            ]
          }
        }
      )
    )
  end

  def run
    usr_tbl = Rex::Text::Table.new(
      'Header' => 'Current User',
      'Indent' => 1,
      'Columns' => ['Is Admin', 'Is System', 'Is In Local Admin Group', 'UAC Enabled', 'Foreground ID', 'UID']
    )

    begin
      # Older OS might not have this (min support is XP)
      fid = client.railgun.kernel32.WTSGetActiveConsoleSessionId['return']
    rescue StandardError
      fid = 'N/A'
    end

    usr_tbl << [
      is_admin?.to_s.capitalize,
      system?.to_s.capitalize,
      is_in_admin_group?.to_s.capitalize,
      is_uac_enabled?.to_s.capitalize,
      fid,
      client.sys.config.getuid
    ]

    privs_tbl = Rex::Text::Table.new(
      'Header' => 'Windows Privileges',
      'Indent' => 1,
      'Columns' => ['Name']
    )

    privs = client.sys.config.getprivs
    privs.each do |priv|
      privs_tbl << [priv]
    end

    print_line(usr_tbl.to_s)
    print_line(privs_tbl.to_s)
  end
end
