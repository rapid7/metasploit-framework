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
  #include Msf::Auxiliary::DRDoS

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

  def short(v)
    [ (v & 0xFF00) >> 8, v & 0x00FF ].pack("CC")
  end

  def build_probe(qname, qtype, qclass)
      short(rand(0xFFF)) + # transaction ID
      "\x00\x00" + # flags
      "\x00\x01" + # questions
      "\x00\x00" + # answer RRs
      "\x00\x00" + # authority RRs
      "\x00\x00" + # additional RRs
      [ qname.length, qname ].pack("Ca#{qname.length+1}") +  # name
      short(qtype) +  # type
      short(qclass)  # class
  end

  def scanner_process(data, shost, _sport)
    @results[shost] ||= []
    @results[shost] << data
  end

  def scan_host(ip)
    scanner_send(build_probe(datastore['NAME'], datastore['TYPE'], datastore['CLASS']), ip, datastore['RPORT'])
  end

  def scanner_prescan(batch)
    @results = {}
    print_status("Sending LLMNR queries to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  def scanner_postscan(_batch)
    @results.keys.each do |k|
      print_good("#{k} responded with #{@results[k].inspect}")
    end
  end
end
