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
      'Name'        => 'NTP PEER_LIST_SUM DoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "PEER_LIST_SUM" queries and
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
    scanner_send(@probe, ip, datastore['RPORT'])
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    this_peer = "#{shost}:#{sport}"
    # sanity check that the reply is not overly large/small
    if data.length < 8
      print_error("#{this_peer} -- suspiciously small (#{data.length} bytes) NTP PEER_LIST_SUM response")
      return
    elsif data.length > 500
      print_error("#{this_peer} -- suspiciously large (#{data.length} bytes) NTP PEER_LIST_SUM response")
      return
    end

    # try to parse this response, alerting and aborting if it is invalid
    response = Rex::Proto::NTP::NTPPrivate.new(data)
    unless [ @version, @implementation, @request_code ] == [ response.version, response.implementation, response.request_code ]
      print_error("#{this_peer} -- unexpected NTP PEER_LIST_SUM response: #{response.inspect}")
      return
    end

    if response.error != 0
      vprint_status("#{this_peer} -- error #{response.error} response to NTP PEER_LIST request")
      return
    end

    if response.record_size != 72 || response.record_count == 0 || response.record_count > 9
      print_error("#{this_peer} -- suspicious NTP PEER_LIST_SUM response with #{response.record_count} #{response.record_size}-byte entries: #{response.inspect}")
      return
    end

    these_results = []
    response.records.each do |record|
      # TODO: Rex this
      # u_int32 dstadr;         /* local address (zero for undetermined) */
      # u_int32 srcadr;         /* source address */
      # u_short srcport;        /* source port */
      # u_char stratum;         /* stratum of peer */
      # s_char hpoll;           /* host polling interval */
      # s_char ppoll;           /* peer polling interval */
      # u_char reach;           /* reachability register */
      # u_char flags;           /* flags, from above */
      # u_char hmode;           /* peer mode */
      # s_fp delay;             /* peer.estdelay */ (int32)
      # l_fp offset;            /* peer.estoffset */ (2x int32)
      # u_fp dispersion;        /* peer.estdisp */ (u_int32)
      # u_int v6_flag;                  /* is this v6 or not */
      # u_int unused1;                  /* (unused) padding for dstadr6 */
      # struct in6_addr dstadr6;        /* local address (v6) */
      # struct in6_addr srcadr6;        /* source address (v6) */

      dst_addr4, src_addr4, src_port, stratum = record[0,12].unpack('NNnC')
      is_v6 = record[32,4].unpack('N').first

      if is_v6 == 0
        src_addr = Rex::Socket.addr_itoa(src_addr4)
      else
        # XXX: is there a better way to do this?
        src_addr6_parts = record[52, 16].unpack("N*")
        src_addr6 = 0
        0.upto(3) do |off|
          src_addr6 = src_addr6 | src_addr6_parts[off]
          src_addr6 <<= 32
        end
        src_addr = Rex::Socket.addr_itoa(src_addr6, true)
      end
      these_results << [ src_addr, src_port, stratum]
      if datastore['SHOW_LIST']
        print_status("#{this_peer} peers with #{src_addr}:#{src_port} (stratum #{stratum})")
      end
    end

    @results[shost] ||= []
    @results[shost] << these_results

  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @version = 2
    @implementation = 3
    @request_code = 1
    @probe = Rex::Proto::NTP.ntp_private(@version, @implementation, @request_code)
    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      peers = packets.flatten(1)
      print_good("#{k}:#{rport} NTP PEER_LIST_SUM request permitted (#{packets.size} packets with #{peers.size} peers total)")
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
        :type  => 'ntp.peer_list_sum',
        :data  => {:peer_list_sum => @results[k]}
      )
    end
  end
end
