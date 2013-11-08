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
      'Description' => 'Obtain the list of recent clients from an NTP server',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(123),
      Opt::CHOST,
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256])
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

    print_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")

    begin
      udp_sock = nil
      idx = 0

      # Create an unbound UDP socket if no CHOST is specified, otherwise
      # create a UDP socket bound to CHOST (in order to avail of pivoting)
      udp_sock = Rex::Socket::Udp.create( { 'LocalHost' => datastore['CHOST'] || nil, 'Context' => {'Msf' => framework, 'MsfExploit' => self} })
      add_socket(udp_sock)

      # Try three times since NTP servers can be a bit busy
      1.upto(3)  do
      batch.each do |ip|
        next if @results[ip]

        begin
          data = probe_pkt_ntp(ip)
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
          report_note(:host => maddr, :type => 'ntp.client.history', :data => {:address => maddr, :port => mport, :server => mserv})
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
    ntp_flags, ntp_auth, ntp_vers, ntp_code = data.slice!(0,4).unpack('C*')
    pcnt, plen, hlen, tmp = data.slice!(0,12).unpack('nnNN')
    return if plen != 72

    idx = 0
    1.upto(pcnt) do
      tmp1,mcnt,madd,sadd,tmp3,tmp4,mport = data[idx, plen].unpack("NNNNn3")
      @results[host] ||= []
      @aliases[host] ||= {}
      @results[host] << [ Rex::Socket.addr_itoa(madd), mport, Rex::Socket.addr_itoa(sadd) ]
      @aliases[host][Rex::Socket.addr_itoa(sadd)] = true
      print_status("#{host}:#{port} #{Rex::Socket.addr_itoa(madd)}:#{mport} (#{Rex::Socket.addr_itoa(sadd)})")
      idx += plen
    end
  end


  def probe_pkt_ntp(ip)
    data =
      "\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return data
  end

end
