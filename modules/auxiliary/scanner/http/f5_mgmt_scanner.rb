##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        'Name'          => 'F5 management interface scanner',
        'Description'   => %q{
          This module simply detects web management interface of the following F5 Networks devices: BigIP, BigIQ, Enterprise Manager, ARX, and FirePass.
        },
        'License'       => MSF_LICENSE,
        'Author'         =>
          [
           'Denis Kolegov <dnkolegov[at]gmail.com>',
           'Oleg Broslavsky <ovbroslavsky[at]gmail.com>',
           'Nikita Oleksov <neoleksov[at]gmail.com>'
           ]
    )
    register_options([
        OptPort.new('RPORT', [true, "The target port", 443]),
        OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500]),
      ], self.class)

    register_advanced_options([
        OptBool.new('SSL', [true, "Negotiate SSL/TLS connection", true]),
        OptEnum.new('SSLVersion', [false, 'Specify the version of SSL/TLS that should be used', 'TLS1', ['SSL2', 'SSL3', 'TLS1']]),
      ], self.class)

    deregister_options('PCAPFILE', 'FILTER', 'INTERFACE', 'SNAPLEN')

  end

  def buildprobe(shost, sport, dhost, dport)
    p = PacketFu::TCPPacket.new
    p.ip_saddr = shost
    p.ip_daddr = dhost
    p.tcp_sport = sport
    p.tcp_flags.ack = 0
    p.tcp_flags.syn = 1
    p.tcp_dport = dport
    p.tcp_win = 3072
    p.recalc
    p
  end

  def probereply(pcap, to)
    reply = nil
    begin
      Timeout.timeout(to) do
        pcap.each do |r|
          pkt = PacketFu::Packet.parse(r)
          next unless pkt.is_tcp?
          reply = pkt
          break
        end
      end
    rescue Timeout::Error
    end
    return reply
  end


  def run_host(ip)
    # Test if a port on a remote host is reachable using TCP SYN method

    open_pcap
    pcap = self.capture

    shost = Rex::Socket.source_address(rhost)
    sport = rand(0xffff - 1025) + 1025
    to = (datastore['TIMEOUT'] || 500).to_f / 1000.0
    self.capture.setfilter("tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and src host #{rhost} and src port #{rport} and dst host #{shost} and dst port #{sport}")

    probe = buildprobe(shost, sport, rhost, rport)
    capture_sendto(probe, rhost)
    reply = probereply(self.capture, to)

    if (reply and reply.is_tcp? and reply.tcp_flags.syn == 1 and reply.tcp_flags.ack == 1)
      
      res = send_request_raw('method' => 'GET', 'uri' => '/', 'rport' => rport)

      if res and res.code == 200

        # Detect BigIP management interface
        if res.body =~ /<title>BIG\-IP/
          print_status("#{peer} - F5 BigIP web management interface found")
          return
        end

        # Detect EM management interface
        if res.body =~ /<title>Enterprise Manager/
          print_status("#{peer} - F5 Enterprise Manager web management interface found")
          return
        end

        # Detect ARX management interface
        if res.body =~ /<title>F5 ARX Manager Login<\/title>/
          print_status("#{peer} - ARX web management interface found")
          return
        end
      end

      res = send_request_raw('method' => 'GET', 'uri' => '/ui/login/', 'rport' => rport)

      # Detect BigIQ management interface
      if res and res.code == 200 and res.body =~ /<title>BIG\-IQ/
        print_status("#{peer} - F5 BigIQ web management interface found")
        return
      end
      # Detect FirePass management interface
      res = send_request_raw('method' => 'GET', 'uri' => '/admin/', 'rport' => rport)
      if res and res.code == 200 and res.body =~ /<br><br><br><big><b>&nbsp;FirePass/
        print_status("#{peer} - F5 FirePass web management interface found")
        return
      end

    end

    rescue ::Rex::ConnectionRefused,
           ::Rex::ConnectionError,
           ::Rex::HostUnreachable,
           ::Errno::ECONNRESET
    print_error("#{peer} - Connection failed")
    rescue ::OpenSSL::SSL::SSLError
     print_error("#{peer} - SSL/TLS connection error")

  end
end
