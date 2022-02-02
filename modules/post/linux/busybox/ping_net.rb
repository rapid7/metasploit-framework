##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize
    super(
      'Name'         => 'BusyBox Ping Network Enumeration',
      'Description'  => %q{
        This module will be applied on a session connected to a BusyBox shell. It will ping a range
        of IP addresses from the router or device executing BusyBox.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptAddressRange.new('RANGE', [true, 'IP range to ping'])
      ])
  end

  def run
    results = ''
    Rex::Socket::RangeWalker.new(datastore['RANGE']).each do |ip|
      vprint_status("Checking address #{ip}")
      results << cmd_exec("ping -c 1 #{ip}")
    end

    p = store_loot('busybox.enum.network', 'text/plain', session, results, 'ping_results.txt', 'BusyBox Device Network Range Enumeration')
    print_good("Results saved to #{p}.")
  end
end
