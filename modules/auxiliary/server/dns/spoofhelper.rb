##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'resolv'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'DNS Spoofing Helper Service',
      'Description' => %q{
        This module provides a DNS service that returns TXT
        records indicating information about the querying service.
        Based on Dino Dai Zovi DNS code from Karma.
      },
      'Author' => ['hdm', 'ddz'],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Service', { 'Description' => 'Run DNS spoofing server' } ]
      ],
      'PassiveActions' => [
        'Service'
      ],
      'DefaultAction' => 'Service',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 53 ]),
      ]
    )
  end

  def run
    @targ = datastore['TARGETHOST']

    if @targ && @targ.strip.empty?
      @targ = nil
    end

    @port = datastore['SRVPORT'].to_i

    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    @sock = ::UDPSocket.new
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind(datastore['SRVHOST'], @port)
    @run = true

    while @run
      packet, addr = @sock.recvfrom(65535)

      break if packet.empty?

      reply = false
      names = []
      request = Resolv::DNS::Message.decode(packet)

      request.each_question do |name, typeclass|
        tc_s = typeclass.to_s.gsub(/^Resolv::DNS::Resource::/, '')

        request.qr = 1
        request.ra = 1

        names << "IN #{tc_s} #{name}"
        case tc_s
        when 'IN::TXT'
          print_status("#{Time.now} PASSED #{addr[3]}:#{addr[1]} XID #{request.id} #{name}")
          answer = Resolv::DNS::Resource::IN::TXT.new("#{addr[3]}:#{addr[1]} #{names.join(',')}")
          request.add_answer(name, 1, answer)
          reply = true
        end
      end

      if reply
        @sock.send(request.encode, 0, addr[3], addr[1])
      else
        print_status("#{Time.now} IGNORE #{addr[3]}:#{addr[1]} XID #{request.id} #{names.join(',')}")
      end
    end
  rescue StandardError => e
    print_error("spoofhelper: #{e.class} #{e} #{e.backtrace}")
  ensure
    # Make sure the socket gets closed on exit
    @sock.close
  end
end
