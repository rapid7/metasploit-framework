##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::DRDoS

  def initialize
    super(
      'Name'        => 'DNS Amplification Scanner',
      'Description' => %q{
          This module can be used to discover DNS servers which expose recursive
          name lookups which can be used in an amplification attack against a
          third party.
      },
      'Author'      => [ 'xistence <xistence[at]0x90.nl>'], # Original scanner module
      'License'     => MSF_LICENSE,
      'References'  =>
          [
              ['CVE', '2006-0987'],
              ['CVE', '2006-0988'],
          ]
    )

    register_options( [
      Opt::RPORT(53),
      OptString.new('DOMAINNAME', [true, 'Domain to use for the DNS request', 'isc.org' ]),
      OptString.new('QUERYTYPE', [true, 'Query type(A, NS, SOA, MX, TXT, AAAA, RRSIG, DNSKEY, ANY)', 'ANY' ]),
    ])
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
    print_status("Sending #{sendpacketsize} bytes to each host using the IN #{datastore['QUERYTYPE']} #{datastore['DOMAINNAME']} request")
    @results = {}
  end

  def scan_host(ip)
    if spoofed?
      datastore['ScannerRecvWindow'] = 0
      scanner_spoof_send(@msearch_probe, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@msearch_probe, ip, datastore['RPORT'])
    end
  end

  def scanner_process(data, shost, sport)

    # Check the response data for \x09\x8d and the next 2 bytes, which contain our DNS flags
    if data =~/\x09\x8d(..)/
      flags = $1
      flags = flags.unpack('B*')[0].scan(/./)
      # Query Response
      qr = flags[0]
      # Recursion Available
      ra = flags[8]
      # Response Code
      rcode = flags[12] + flags[13] + flags[14] + flags[15]

      # If these flags are set, we get a valid response
      # don't test recursion available if correct answer received
      # at least the case with bind and "additional-from-cache no" or version < 9.5+
      if qr == "1" and rcode == "0000"
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
          :refs => self.references)
      end

      # If these flags are set, we get a valid response but recursion is not available
      if qr == "1" and ra == "0" and rcode == "0101"
        print_status("#{shost}:#{datastore['RPORT']} - Recursion not allowed")
        report_service(:host => shost, :port => datastore['RPORT'], :proto => 'udp', :name => "dns")
      end
    end
  end
end
