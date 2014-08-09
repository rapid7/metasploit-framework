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
      'Name'        => 'NTP GET_RESTRICT DoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "reslist" queries and
        obtains the list of restrictions placed on various network interfaces,
        networks or hosts.  The reslist feature allows remote
        attackers to cause a denial of service (traffic amplification) via
        spoofed requests. The more interfaces, networks or host with specific
        restrictions, the greater the amplification.
      },
      'References'  =>
        [
        ],
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptBool.new('SHOW_LIST', [false, 'Show the restrictions list', 'false'])
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
    if data.length < 12
      print_error("#{this_peer} -- suspiciously small (#{data.length} bytes) NTP reslist response")
      return
    elsif data.length > 500
      print_error("#{this_peer} -- suspiciously large (#{data.length} bytes) NTP reslist response")
      return
    end

    # try to parse this response, alerting and aborting if it is invalid
    response = Rex::Proto::NTP::NTPPrivate.new(data)
    unless [ @version, @implementation, @request_code ] == [ response.version, response.implementation, response.request_code ]
      print_error("#{this_peer} -- unexpected NTP reslist response: #{response.inspect}")
      return
    end

    if response.record_size != 56 || response.record_count == 0 || response.record_count > 9
      print_error("#{this_peer} -- suspicious NTP reslist response with #{response.record_count} #{response.record_size}-byte entries: #{response.inspect}")
      return
    end

    these_results = []
    response.records.each do |record|
      # TODO: Rex this
      # u_int32 addr;           /* match address */
      # u_int32 mask;           /* match mask */
      # u_int32 count;          /* number of packets matched */
      # u_short flags;          /* restrict flags */
      # u_short mflags;         /* match flags */
      # u_int v6_flag;          /* is this v6 or not */
      # u_int unused1;          /* unused, padding for addr6 */
      # struct in6_addr addr6;  /* match address (v6) */
      # struct in6_addr mask6;  /* match mask (v6) */

      addr4, mask4, count, rflags, mflags, is_v6 = record[0,20].unpack("NNNnnnn")

      if is_v6 == 0
        addr = Rex::Socket.addr_itoa(addr4)
        mask = Rex::Socket.addr_itoa(mask4)
      else
        # XXX: is there a better way to do this?
        addr6_parts = record[20, 16].unpack("N*")
        mask6_parts = record[36, 16].unpack("N*")
        addr6 = 0
        mask6 = 0
        0.upto(3) do |off|
          addr6 = addr6 | addr6_parts[off]
          addr6 <<= 32
          mask6 = mask6 | mask6_parts[off]
          mask6 <<= 32
        end
        addr = Rex::Socket.addr_itoa(addr6, true)
        mask = Rex::Socket.addr_itoa(mask6, true)
      end
      these_results << [ addr, mask, rflags, mflags]
      if datastore['SHOW_LIST']
        print_status("#{this_peer} #{addr}/#{mask} (count: #{count}, restrict flags: #{rflags}, match flags: #{mflags})")
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
    @request_code = 16
    @probe = Rex::Proto::NTP.ntp_private(@version, @implementation, @request_code)
    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      entries = packets.flatten(1)
      print_good("#{k}:#{rport} NTP reslist request permitted (#{packets.size} packets with #{entries.size} total entries)")
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
        :type  => 'ntp.reslist',
        :data  => {:reslist => @results[k]}
      )
    end
  end
end
