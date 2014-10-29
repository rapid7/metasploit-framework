##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::LLMNR

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'LLMNR Query',
      'Description'    => %q(
      ),
      'Author'         =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>'
        ],
      'License'        => MSF_LICENSE,
      )
    )
    register_options(
      [
        OptString.new('NAME', [ true, 'The name to query', 'localhost' ]),
        OptInt.new('TYPE', [ true, 'The query type #', 255 ]),
        OptInt.new('CLASS', [ true, 'The query class #', 1 ])
      ], self.class)
  end

  def setup
    @probe = ::Net::DNS::Packet.new(datastore['NAME'], datastore['TYPE'], datastore['CLASS']).data
  end

  def scanner_process(data, shost, _sport)
    @results[shost] ||= []
    @results[shost] << data
  end

  def scan_host(ip)
    scanner_send(@probe, ip, datastore['RPORT'])
  end

  def scanner_prescan(batch)
    @results = {}
    print_status("Sending LLMNR queries to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  def scanner_postscan(_batch)
    @results.each_pair do |peer, resps|
      resps.each do |resp|
        print_good("#{peer} responded with #{Resolv::DNS::Message.decode(resp).inspect}")
      end
    end
  end
end
