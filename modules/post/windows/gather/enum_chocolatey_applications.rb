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
        'SessionTypes' => %w[meterpreter shell],
        'Notes' => {
          'Stability' => 'This command works correctly for all versions of chocolatey and works on a regular shell as well as a meterpreter',
          'Reliability' => 'Uses the exact commands chocolatey uses to list installed packages',
          'SideEffects' => 'No side effects. No files placed anywhere or anything.'
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('ChocoPath', [false, 'The path to the chocolaty executable if its not on default path', 'choco.exe'])
      ]
    )
  end

  def chocopath
    # cmd_exec('where.exe', 'choco.exe') unless chocolatey?
    begin
      if chocolatey?
        datastore['ChocoPath']
      end
    rescue
      cmd_exec('where.exe', 'choco.exe')
    end
  end

  def chocolatey?
    cmd_exec(datastore['ChocoPath'], '-v') =~ /\d+\.\d+\.\d+/m
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
    data = if choco_version.match(/^1\.\d+\.\d+$/)
             # its version 1, use local only
             cmd_exec(chocopath, 'list -lo')
           else
             # its version 2 or above, no need for local
             cmd_exec(chocopath, 'list')
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
    p = store_loot('host.applications', 'text/plain', session, results, 'chocolatey_applications.txt',
                   'Applications Installed with Chocolatey')
    print_good("Results stored in: #{p}")
  end
end
