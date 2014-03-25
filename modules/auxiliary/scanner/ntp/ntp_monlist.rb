##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

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
      Opt::RPORT(123),
      Opt::CHOST,
      OptInt.new('RETRY', [false, "Number of tries to query the NTP server", 3]),
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptBool.new('SHOW_LIST', [false, 'Show the recent clients list', 'false'])
    ], self.class)

    register_advanced_options(
    [
      OptBool.new('StoreNTPClients', [true, 'Store NTP clients as host records in the database', 'false'])
    ], self.class)
  end

  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Fingerprint a single host
  def run_batch(batch)

    @results = {}
    @aliases = {}

    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")

    begin
      udp_sock = nil
      idx = 0

      # Create an unbound UDP socket if no CHOST is specified, otherwise
      # create a UDP socket bound to CHOST (in order to avail of pivoting)
      udp_sock = Rex::Socket::Udp.create({
        'LocalHost' => datastore['CHOST'] || nil,
        'Context'   => {'Msf' => framework, 'MsfExploit' => self}
      })
      add_socket(udp_sock)

      # Try more times since NTP servers can be a bit busy
      1.upto(datastore['RETRY'].to_i) do
        batch.each do |ip|
          next if @results[ip]

          begin
            data = probe_pkt_ntp
            udp_sock.sendto(data, ip, datastore['RPORT'].to_i, 0)
          rescue ::Interrupt
            raise $!
          rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
            nil
          end

          if (idx % 30 == 0)
            while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
              parse_reply(r)
            end
          end

          idx += 1
        end
      end

      while (r = udp_sock.recvfrom(65535, 10) and r[1])
        parse_reply(r)
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    end

    @results.keys.each do |k|

      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => datastore['RPORT'].to_i,
        :name  => 'ntp'
      )

      report_note(
        :host  => k,
        :proto => 'udp',
        :port  => datastore['RPORT'].to_i,
        :type  => 'ntp.monlist',
        :data  => {:monlist => @results[k]}
      )

      if (@aliases[k] and @aliases[k].keys[0] != k)
        print_good("#{k}:#{datastore['RPORT'].to_i} NTP monlist request permitted (#{@results[k].length} entries)")
        report_note(
          :host  => k,
          :proto => 'udp',
          :port  => datastore['RPORT'].to_i,
          :type  => 'ntp.addresses',
          :data  => {:addresses => @aliases[k].keys}
        )
      end

      if (datastore['StoreNTPClients'])
        print_status("#{k} Storing #{@results[k].length} NTP client hosts in the database...")
        @results[k].each do |r|
          maddr,mport,mserv = r
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

  end

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

  def probe_pkt_ntp
    "\x17\x00\x03\x2a" + "\x00" * 188
  end

end
