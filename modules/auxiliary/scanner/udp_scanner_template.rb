##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'           => 'UDP Scanner Example',
      'Description'    => %q(
        This module does stuff
      ),
      'Author'         => 'Joe Contributor <joe_contributor[at]example.com>',
      'References'     =>
        [
          ['URL', 'https://example.com/~jcontributor']
        ],
      'DisclosureDate' => 'Mar 15 2014',
      'License'        => MSF_LICENSE
    )
    register_options(
    [
      Opt::RPORT(12345)
    ], self.class)

    register_advanced_options(
    [
      OptBool.new('SPECIAL', [true, 'Try this special thing', false])
    ], self.class)
  end

  # Called for each IP in the batch
  def scan_host(ip)
    if datastore['SPECIAL']
      scanner_send("Please and thank you, #{ip}!", ip, rport)
    else
      scanner_send(@probe, ip, datastore['RPORT'])
    end
  end

  # Called for each response packet
  def scanner_process(data, src_host, src_port)
    @results[src_host] ||= []
    @results[src_host] << data.inspect
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @probe = "abracadabra!"
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.each_pair do |host, responses|

      # consider confirming that any of the responses are actually
      # valid responses for this service before reporing it or
      # examining the responses for signs of a vulnerability
      report_service(
        host: host,
        proto:'udp',
        port: rport,
        name: 'example'
      )

      if responses.any? { |response| response =~ /[a-z0-9]{5}/i }
        print_good("#{peer} - Vulnerable to something!")
        report_vuln(
          host: k,
          port: rport,
          proto: 'udp',
          name: 'something!',
          refs: references
        )
      else
        vprint_status("#{peer} - Not vulnerable to something")
      end
    end
  end
end
