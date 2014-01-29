##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'DNS Amplification Scanner',
      'Description' => 'Discover recursive name servers and amplification possibilities',
      'Author'      => [ 'xistence <xistence[at]0x90.nl>'], # Original scanner module
      'License'     => MSF_LICENSE
    )

    register_options( [
      Opt::RPORT(53),
      OptString.new('DOMAINNAME', [true, 'Domain to use for the DNS request', 'isc.org' ]),
      OptString.new('QUERYTYPE', [true, 'Query type(A, NS, SOA, MX, TXT, AAAA, RRSIG, DNSKEY, ANY)', 'ANY' ]),
    ], self.class)
  end

  def rport
    datastore['RPORT']
  end

  def setup
    super

    # Check for DNS query types byte
    case datastore['QUERYTYPE']
    when 'A'
      querypacket="\x01"
    when 'NS'
      querypacket="\x02"
    when 'SOA'
      querypacket="\x06"
    when 'MX'
      querypacket="\x0f"
    when 'TXT'
      querypacket="\x10"
    when 'AAAA'
      querypacket="\x1c"
    when 'RRSIG'
      querypacket="\x2e"
    when 'DNSKEY'
      querypacket="\x30"
    when 'ANY'
      querypacket="\xff"
    else
      print_error("Invalid query type!")
      return
    end

    targdomainpacket = []
    # Before every part of the domainname there should be the length of that part (instead of a ".")
    # So isc.org divided is 3isc3org
    datastore['DOMAINNAME'].split('.').each do |domainpart|
      # The length of the domain part in hex
      domainpartlength =  "%02x" % domainpart.length
      # Convert the name part to a hex string
      domainpart = domainpart.each_byte.map { |b| b.to_s(16) }.join()
      # Combine the length of the name part and the name part
      targdomainpacket.push(domainpartlength + domainpart)
    end
    # Convert the targdomainpacket to a string
    targdomainpacket = targdomainpacket.join.to_s
    # Create a correct hex character string to be used in the packet
    targdomainpacket = targdomainpacket.scan(/../).map { |x| x.hex.chr }.join
    # DNS Packet including our target domain and query type
    @msearch_probe = "\x09\x8d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + targdomainpacket + "\x00\x00" + querypacket + "\x00\x01"
  end

  def scanner_prescan(batch)
    print_status("Sending DNS probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    # Standard packet is 60 bytes. Add the domain size to this
    sendpacketsize = 60 + datastore['DOMAINNAME'].length
    print_status("Sending #{sendpacketsize} bytes to each host using the IN ANY #{datastore['DOMAINNAME']} request")
    @results = {}
  end

  def scan_host(ip)
    scanner_send(@msearch_probe, ip, datastore['RPORT'])
  end

  def scanner_process(data, shost, sport)
    # If data doesn't contain \x09\x8d\x81\x05 (query refused) then display amplification size
    if data =~/\x09\x8d\x81\x05/
      print_status("#{shost}:#{datastore['RPORT']} - Recursion not allowed")
      report_service(:host => shost, :port => datastore['RPORT'], :proto => 'udp', :name => "dns")
    else
      sendlength = 60 + datastore['DOMAINNAME'].length
      receivelength = 42 + data.length
      amp = receivelength / sendlength.to_f
      print_good("#{shost}:#{datastore['RPORT']} - Response is #{receivelength} bytes [#{amp.round(2)}x Amplification]")
      report_service(:host => shost, :port => datastore['RPORT'], :proto => 'udp', :name => "dns")
      report_vuln(
        :host => shost,
        :port => datastore['RPORT'],
        :proto => 'udp', :name => "DNS",
        :info => "DNS amplification -  #{data.length} bytes [#{amp.round(2)}x Amplification]",
        :refs => [ "CVE-2006-0987", "CVE-2006-0988" ])
    end
  end
end
