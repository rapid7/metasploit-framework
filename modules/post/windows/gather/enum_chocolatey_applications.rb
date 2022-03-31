# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Installed Application Within Chocolatey Enumeration',
        'Description' => ' This module will enumerate all installed applications on a Windows system with chocolatey installed ',
        'License' => MSF_LICENSE,
        'Author' => ['Nick Cottrell <ncottrellweb@gmail.com>'],
        'Platform' => ['win'],
        'Privileged' => false,
        'SessionTypes' => %w[meterpreter shell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('ChocoPath', [false, 'The path to the chocolatey executable if it\'s not on default path', 'choco.exe']),
      ]
    )
  end

  def chocopath
    # cmd_exec('where.exe', 'choco.exe') unless chocolatey?

    if !chocolatey?
    cmd_exec('where.exe', 'choco.exe')
  end
  end

  def chocolatey?
    !!(cmd_exec(datastore['ChocoPath'], '-v') =~ /\d+\.\d+\.\d+/m)
  rescue Rex::Post::Meterpreter::RequestError
    false
  end

  def run
    # checking that session is meterpreter and session has powershell
    return 0 unless chocopath

    print_status("Enumerating applications installed on #{sysinfo['Computer']}") if session.type == 'meterpreter'

    # getting chocolatey version
    choco_version = cmd_exec(chocopath, '-v')
    print_status("Targets Chocolatey version: #{choco_version}")

    # Getting results of listing chocolatey applications
    print_status('Getting chocolatey applications.')

    # checking if chocolatey is 2+ or 1.0.0
    data = if choco_version.match(/^[10]\.\d+\.\d+$/)
             # its version 1, use local only
             cmd_exec(chocopath, 'list -lo')
           elsif choco_version.match(/^(?:[2-9]|\d{2,})\.\d+\.\d+$/)
             # its version 2 or above, no need for local
             cmd_exec(chocopath, 'list')
           else
             print_bad('Failed to get chocolatey version. It gave result that we did not expect.')
             print_line(cmd_exec(choco_version))
             return 0
           end
    print_good('Successfully grabbed all items')

    # making table to better organize applications and their versions
    table = Rex::Text::Table.new(
      'Header' => 'Installed Chocolatey Applications',
      'Indent' => 1,
      'Columns' => %w[
        Name
        Version
      ]
    )

    # collecting all lines that match and placing them into table.
    items = data.scan(/(\S+)\s(\d+(?:\.\d+)*)/m)
    items.each do |set|
      table << set
    end
    results = table.to_s

    # giving results
    print_line(results.to_s)
    report_note(
      host: session.session_host,
      type: 'chocolatey.software.enum',
      data: items,
      update: :unique_data
    )
  end
end
