##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'resolv'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report


  def initialize
    super(
      'Name'        => 'Fake DNS Service',
      'Description'    => %q{
        This module provides a DNS service that redirects
      all queries to a particular address.
      },
      'Author'      => ['ddz', 'hdm', 'fozavci'],
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
        OptAddress.new('TARGETHOST', [ false, "The address that all names should resolve to", nil ]),
        OptString.new('TARGETDOMAIN', [ true, "The list of target domain names we want to fully resolve (BYPASS) or fake resolve (FAKE)", 'www.google.com']),
        OptEnum.new('TARGETACTION', [ true, "Action for TARGETDOMAIN", "BYPASS", %w{FAKE BYPASS}]),
      ])

    register_advanced_options(
      [
        OptPort.new('RR_SRV_PORT', [ false, "The port field in the SRV response when FAKE", 5060]),
        OptBool.new('LogConsole', [ false, "Determines whether to log all request to the console", true]),
        OptBool.new('LogDatabase', [ false, "Determines whether to log all request to the database", false]),
      ])
  end


  def target_host(addr = nil)
    target = datastore['TARGETHOST']
    if target.blank?
      if addr
        ::Rex::Socket.source_address(addr)
      else
        nil
      end
    else
      ::Rex::Socket.resolv_to_dotted(target)
    end
  end

  def run
    @port = datastore['SRVPORT'].to_i

    @log_console  = false
    @log_database = false

    if datastore['LogConsole']
      @log_console = true
    end

    if datastore['LogDatabase']
      @log_database = true
    end

    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    print_status("DNS server initializing")
    @sock = ::UDPSocket.new()
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind(datastore['SRVHOST'], @port)
    @run = true
    @domain_target_list = datastore['TARGETDOMAIN'].split
    @bypass = ( datastore['TARGETACTION'].upcase == "BYPASS" )

    print_status("DNS server started")
    begin

    while @run
      @error_resolving = false
      packet, addr = @sock.recvfrom(65535)
      src_addr = addr[3]
      @requestor = addr
      next if packet.length == 0

      request = Resolv::DNS::Message.decode(packet)
      next unless request.qr == 0

      #
      # XXX: Track request IDs by requesting IP address and port
      #
      # Windows XP SP1a: UDP source port constant,
      #  sequential IDs since boot time
      # Windows XP SP2: Randomized IDs
      #
      # Debian 3.1: Static source port (32906) until timeout,
      #  randomized IDs
      #

      lst = []

      request.each_question {|name, typeclass|
        # Identify potential domain exceptions
        @match_target = false
        @match_name = name.to_s
        @domain_target_list.each do |ex|
          escaped = Regexp.escape(ex).gsub('\*','.*?')
          regex = Regexp.new "^#{escaped}$", Regexp::IGNORECASE
          if ( name.to_s =~ regex )
            @match_target = true
            @match_name = ex
          end
        end

        tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")

        request.qr = 1
        request.ra = 1

        lst << "#{tc_s} #{name}"
        case tc_s
        when 'IN::A'

          # Special fingerprinting name lookups:
          #
          # _isatap -> XP SP = 0
          # isatap.localdomain -> XP SP >= 1
          # teredo.ipv6.microsoft.com -> XP SP >= 2
          #
          # time.windows.com -> windows ???
          # wpad.localdomain -> windows ???
          #
          # <hostname> SOA -> windows XP self hostname lookup
          #

          answer = Resolv::DNS::Resource::IN::A.new(target_host(src_addr))

          if (@match_target and not @bypass) or (not @match_target and @bypass)
            # Resolve FAKE response
            if (@log_console)
              print_status("DNS target domain #{@match_name} found; Returning fake A records for #{name}")
            end
          else
            # Resolve the exception domain
            begin
            ip = Resolv::DNS.new().getaddress(name).to_s
            answer = Resolv::DNS::Resource::IN::A.new( ip )
            rescue ::Exception => e
              @error_resolving = true
              next
            end
            if (@log_console)
              print_status("DNS bypass domain #{@match_name} found; Returning real A records for #{name}")
            end
          end


          request.add_answer(name, 60, answer)

        when 'IN::MX'
          mx = Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mail.#{name}"))
          ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
          ar = Resolv::DNS::Resource::IN::A.new(target_host(src_addr))
          request.add_answer(name, 60, mx)
          request.add_authority(name, 60, ns)
          request.add_additional(Resolv::DNS::Name.create("mail.#{name}"), 60, ar)

        when 'IN::NS'
          ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
          ar = Resolv::DNS::Resource::IN::A.new(target_host(src_addr))
          request.add_answer(name, 60, ns)
          request.add_additional(name, 60, ar)

        when 'IN::SRV'
          if @bypass || !@match_target
            if @log_console
              print_status("DNS bypass domain #{@match_name} found; Returning real SRV records for #{name}")
            end
            # if we are in bypass mode or we are in fake mode but the target didn't match,
            # just return the real response RRs
            resources = Resolv::DNS.new().getresources(Resolv::DNS::Name.create(name), Resolv::DNS::Resource::IN::SRV)
            if resources.empty?
              @error_resolving = true
              print_error("Unable to resolve SRV record for #{name} -- skipping")
              next
            end
            resources.each do |resource|
              host = resource.target
              port = resource.port.to_i
              weight = resource.weight.to_i
              priority = resource.priority.to_i
              ttl = resource.ttl.to_i
              request.add_answer(
                name,
                ttl,
                Resolv::DNS::Resource::IN::SRV.new(priority, weight, port, Resolv::DNS::Name.create(host))
              )
            end
          else
            if @log_console
              print_status("DNS target domain #{@match_name} found; Returning fake SRV records for #{name}")
              # Prepare the FAKE response
              request.add_answer(
                name,
                10,
                Resolv::DNS::Resource::IN::SRV.new(5, 0, datastore['RR_SRV_PORT'], Resolv::DNS::Name.create(name))
              )
              request.add_additional(Resolv::DNS::Name.create(name), 60, Resolv::DNS::Resource::IN::A.new(target_host(src_addr)))
            end
          end
        when 'IN::PTR'
          soa = Resolv::DNS::Resource::IN::SOA.new(
            Resolv::DNS::Name.create("ns.internet.com"),
            Resolv::DNS::Name.create("root.internet.com"),
            1,
            3600,
            3600,
            3600,
            3600
          )
          ans = Resolv::DNS::Resource::IN::PTR.new(
            Resolv::DNS::Name.create("www")
          )

          request.add_answer(name, 60, ans)
          request.add_authority(name, 60, soa)
        else
          lst << "UNKNOWN #{tc_s}"
        end
      }

      if(@log_console)
        if(@error_resolving)
          print_error("XID #{request.id} (#{lst.join(", ")}) - Error resolving")
        else
          print_status("XID #{request.id} (#{lst.join(", ")})")
        end
      end

      if(@log_database)
        report_note(
          :host => addr[3],
          :type => "dns_lookup",
          :data => "#{addr[3]}:#{addr[1]} XID #{request.id} (#{lst.join(", ")})"
        ) if lst.length > 0
      end


      @sock.send(request.encode(), 0, addr[3], addr[1])
    end

    rescue ::Exception => e
      print_error("fakedns: #{e.class} #{e} #{e.backtrace}")
    # Make sure the socket gets closed on exit
    ensure
      @sock.close
    end
  end

  def print_error(msg)
    @requestor ? super("%s:%p - DNS - %s" % [@requestor[3], @requestor[1], msg]) : super(msg)
  end

  def print_status(msg)
    @requestor ? super("%s:%p - DNS - %s" % [@requestor[3], @requestor[1], msg]) : super(msg)
  end
end
