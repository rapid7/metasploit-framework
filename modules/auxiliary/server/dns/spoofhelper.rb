##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'resolv'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report


  def initialize
    super(
      'Name'        => 'DNS Spoofing Helper Service',
      'Description'    => %q{
        This module provides a DNS service that returns TXT
      records indicating information about the querying service.
      Based on Dino Dai Zovi DNS code from Karma.

      },
      'Author'      => ['hdm', 'ddz'],
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
        OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 53 ]),
      ])
  end


  def run
    @targ = datastore['TARGETHOST']

    if(@targ and @targ.strip.length == 0)
      @targ = nil
    end

    @port = datastore['SRVPORT'].to_i

    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    @sock = ::UDPSocket.new()
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind(datastore['SRVHOST'], @port)
    @run = true

    # Wrap in exception handler
    begin
      while @run
        reply = false
        packet, addr = @sock.recvfrom(65535)
        if (packet.length == 0)
          break
        end

        names = []
        request = Resolv::DNS::Message.decode(packet)

        request.each_question {|name, typeclass|
          tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")

          request.qr = 1
          request.ra = 1

          names << "IN #{tc_s} #{name}"
          case tc_s
          when 'IN::TXT'
            print_status("#{Time.now} PASSED #{addr[3]}:#{addr[1]} XID #{request.id} #{name}")
            answer = Resolv::DNS::Resource::IN::TXT.new("#{addr[3]}:#{addr[1]} #{names.join(",")}")
            request.add_answer(name, 1, answer)
            reply = true
          end
        }

        if(reply)
          @sock.send(request.encode(), 0, addr[3], addr[1])
        else
          print_status("#{Time.now} IGNORE #{addr[3]}:#{addr[1]} XID #{request.id} #{names.join(",")}")
        end
      end

    # Make sure the socket gets closed on exit
    rescue ::Exception => e
      print_error("spoofhelper: #{e.class} #{e} #{e.backtrace}")
    ensure
      @sock.close
    end
  end
end
