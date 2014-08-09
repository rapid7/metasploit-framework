##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::NTP

  def initialize
    super(
      'Name'        => 'NTP PEER_LIST DoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "PEER_LIST" queries and
        return responses that are larger in size or greater in quantity than
        the request, allowing remote attackers to cause a denial of service
        (traffic amplification) via spoofed requests.
      },
      'References'  =>
        [
        ],
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptBool.new('SHOW_PEERS', [false, 'Show peers', 'false'])
    ], self.class)
  end

  # Called for each IP in the batch
  def scan_host(ip)
    @probes.each do |probe|
      scanner_send(probe, ip, datastore['RPORT'])
    end
  end

  # Called before the scan block
  def scanner_prescan(batch)
    # build a probe for all possible variations of the PEER_LIST request, which
    # means using all combinations of NTP version, mode 7 implementations and
    # with and without payloads.
    @probes = []
    versions = datastore['VERSIONS'].split(/,/).map { |v| v.strip.to_i }
    implementations = datastore['IMPLEMENTATIONS'].split(/,/).map { |i| i.strip.to_i }
    payloads = ['', "\x00"*40]
    versions.each do |v|
      implementations.each do |i|
        payloads.each do |p|
          @probes << Rex::Proto::NTP.ntp_private(v, i, 0, p)
        end
      end
    end
    @results = {}
    vprint_status("Sending #{@probes.size} NTP PEER_LIST probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    this_peer = "#{shost}:#{sport}"
    # sanity check that the reply is not overly large/small
    if data.length < 8
      print_error("#{this_peer} -- suspiciously small (#{data.length} bytes) NTP PEER_LIST response")
      return
    elsif data.length > 500
      print_error("#{this_peer} -- suspiciously large (#{data.length} bytes) NTP PEER_LIST response")
      return
    end

    # try to parse this response, alerting and aborting if it is invalid
    response = Rex::Proto::NTP::NTPPrivate.new(data)
    unless contains_relevant_message?(response, @probes)
      print_error("#{this_peer} -- unexpected NTP PEER_LIST response: #{response.inspect}")
      return
    end

    if response.error != 0
      vprint_status("#{this_peer} -- error #{response.error} response to NTP PEER_LIST request")
      return
    end

    if response.record_size != 32 || response.record_count == 0 || response.record_count > 15
      print_error("#{this_peer} -- suspicious NTP PEER_LIST response with #{response.record_count} #{response.record_size}-byte entries: #{response.inspect}")
      return
    end

    these_results = []
    response.records.each do |record|
      # TODO: Rex this
      # u_int32 addr;           /* address of peer */
      # u_short port;           /* port number of peer */
      # u_char hmode;           /* mode for this peer */
      # u_char flags;           /* flags (from above) */
      # u_int v6_flag;          /* is this v6 or not */
      # u_int unused1;          /* (unused) padding for addr6 */
      # struct in6_addr addr6;  /* v6 address of peer */

      src_addr4, src_port = record[0,6].unpack('Nn')
      is_v6 = record[8,4].unpack('N').first

      if is_v6 == 0
        src_addr = Rex::Socket.addr_itoa(src_addr4)
      else
        # XXX: according to the struct, this should be record[16,16], but that doesn't work.  Why?
        src_addr6_parts = record[12, 16].unpack("N*")
        src_addr6 = 0
        0.upto(3) do |off|
          src_addr6 = src_addr6 | src_addr6_parts[off]
          src_addr6 <<= 32
        end
        src_addr = Rex::Socket.addr_itoa(src_addr6, true)
      end
      these_results << [ src_addr, src_port ]
      if datastore['SHOW_LIST']
        print_status("#{this_peer} peers with #{src_addr}:#{src_port}")
      end
    end

    @results[shost] ||= []
    @results[shost] << these_results

  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      peers = packets.flatten(1)
      print_good("#{k}:#{rport} NTP PEER_LIST request permitted (#{packets.size} packets with #{peers.size} peers total)")
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )

      report_note(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :type  => 'ntp.peer_list',
        :data  => {:peer_list => @results[k]}
      )
    end
  end
end
