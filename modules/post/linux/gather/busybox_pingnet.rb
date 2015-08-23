##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize
    super(
      'Name'         => 'BusyBox Ping Network',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will ping a range of
                         ip adresses from the router or device executing BusyBox.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptAddress.new('IPRANGESTART',   [ true, "The first ip address of the range to ping.", nil ]),
        OptAddress.new('IPRANGEEND',   [ true, "The last ip address of the range to ping.", nil ])
      ], self.class)
  end

  #
  #This module executes the ping command from the BusyBox connected shell for a given range of ip addresses. The
  #results will be stored in loots
  #
  def run

    full_results = ""

    (IPAddr.new(datastore['IPRANGESTART'])..IPAddr.new(datastore['IPRANGEEND'])).map(&:to_s).each do |current_ip_address|
      print_status("Doing ping to the address #{current_ip_address}.")
      full_results << cmd_exec("ping -c 1 #{current_ip_address}")
    end

    #storing results
    p = store_loot("Pingnet", "text/plain", session, full_results, "#{datastore['IPRANGESTART']}"+"-"+"#{datastore['IPRANGEEND']}", "BusyBox Device Network Range Pings")
    print_good("Pingnet results saved to #{p}.")
  end

end
