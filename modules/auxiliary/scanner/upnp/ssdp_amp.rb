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
      'Name'        => 'SSDP ssdp:all Search Text Amplification Scanner',
      'Description' => 'Discover SSDP amplification possibilities',
      'Author'      => [ 'xistence <xistence[at]0x90.nl>'], # Original scanner module
      'License'     => MSF_LICENSE
    )

    register_options( [
      Opt::RPORT(1900),
      OptBool.new('SHORT', [ false, "Does a shorter request, for a higher amplifier, not compatible with all devices", false]),
    ], self.class)
  end

  def rport
    datastore['RPORT']
  end

  def setup
    super
    # SSDP packet containing the "ST:ssdp:all" search query
    if datastore['short']
      # Short packet doesn't contain Host, MX and last \r\n
      @msearch_probe = "M-SEARCH * HTTP/1.1\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\n"
      @req_length = "97"
    else
      @msearch_probe = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:5\r\n\r\n"
      @req_length = "132"
    end
  end

  def scanner_prescan(batch)
    print_status("Sending #{@req_length} bytes SSDP probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    scanner_send(@msearch_probe, ip, datastore['RPORT'])
  end

  def scanner_postscan(batch)
    print_status "No SSDP endpoints found" if @results.empty?
    @results.each_pair {|key,value|
      ampsize = value[:packetsize] / @req_length.to_f
      print_good("#{key} - Response is #{value[:packetsize]} bytes in #{value[:packets]} packets [#{ampsize.round(2)}x Amplification]")
    }
  end

  def scanner_process(data, shost, sport)
    if data =~/HTTP\/1.1 200 OK/
      skey = "#{shost}:#{datastore['RPORT']}"
      @results[skey] ||= {
        :packetsize => 0,
        :packets => 0
      }

      @results[skey][:packetsize] += data.length + 42

      @results[skey][:packets] += 1
    end
  end
end
