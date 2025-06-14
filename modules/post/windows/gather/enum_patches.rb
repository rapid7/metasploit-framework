##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Applied Patches',
        'Description' => %q{
          This module enumerates patches applied to a Windows system using the
          WMI query: SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => [
          'zeroSteiner', # Original idea
          'mubix' # Post module
        ],
        'References' => [
          ['URL', 'http://msdn.microsoft.com/en-us/library/aa394391(v=vs.85).aspx']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              extapi_wmi_query
            ]
          }
        }
      )
    )
  end

  def run
    unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_WMI_QUERY)
      fail_with(Failure::NoTarget, 'Session does not support Meterpreter ExtAPI WMI queries')
    end

    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    begin
      objects = session.extapi.wmi.query('SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering')
    rescue RuntimeError
      fail_with(Failure::BadConfig, 'Known bug in WMI query, try migrating to another process')
    end

    if objects.nil?
      print_error('Could not retrieve patch information. WMI query returned no data.')
      return
    end

    if objects[:values].blank?
      print_status('Found no patches installed')
      return
    end

    results = Rex::Text::Table.new(
      'Header' => 'Installed Patches',
      'Indent' => 2,
      'Columns' =>
      [
        'HotFix ID',
        'Install Date'
      ]
    )

    objects[:values].compact.each do |k|
      results << k
    end

    if results.rows.empty?
      print_status("No patches were found to be installed on #{hostname} (#{session.session_host})")
      return
    end

    print_line
    print_line(results.to_s)

    loot_file = store_loot('enum_patches', 'text/plain', session, results.to_csv)
    print_status("Patch list saved to #{loot_file}")
  end
end
