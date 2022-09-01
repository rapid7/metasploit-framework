##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::NATPMP
  include Rex::Proto::NATPMP

  def initialize
    super(
      'Name'        => 'NAT-PMP Port Mapper',
      'Description' => 'Map (forward) TCP and UDP ports on NAT devices using NAT-PMP',
      'Author'      => 'Jon Hart <jhart[at]spoofed.org>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('EXTERNAL_PORTS', [true, 'The external ports to foward from (0 to let the target choose)', 0]),
        OptString.new('INTERNAL_PORTS', [true, 'The internal ports to forward to', '22,135-139,80,443,445'])
      ],
      self.class
    )
  end

  def build_ports(ports_string)
    # We don't use Rex::Socket.portspec_crack because we need to allow 0 and preserve order
    ports = []
    ports_string.split(/[ ,]/).map { |s| s.strip }.compact.each do |port_part|
      if /^(?<port>\d+)$/ =~ port_part
        ports << port.to_i
      elsif /^(?<low>\d+)\s*-\s*(?<high>\d+)$/ =~ port_part
        ports |= (low..high).to_a.map(&:to_i)
      else
        fail ArgumentError, "Invalid port specification #{port_part}"
      end
    end
    ports
  end

  def setup
    super
    @external_ports = build_ports(datastore['EXTERNAL_PORTS'])
    @internal_ports = build_ports(datastore['INTERNAL_PORTS'])

    if @external_ports.size > @internal_ports.size
      fail ArgumentError, "Too many external ports specified (#{@external_ports.size}); " +
        "must be one port (0) or #{@internal_ports.size} ports"
    end

    if @external_ports.size < @internal_ports.size
      if @external_ports != [0]
        fail ArgumentError, "Incorrect number of external ports specified (#{@external_ports.size}); " +
          "must be one port (0) or #{@internal_ports.size} ports"
      else
        @external_ports = [0] * @internal_ports.size
      end
    end
  end

  def run_host(host)
    begin

      udp_sock = Rex::Socket::Udp.create({
        'LocalHost' => datastore['CHOST'] || nil,
        'Context'   => {'Msf' => framework, 'MsfExploit' => self}
      })
      add_socket(udp_sock)

      external_address = get_external_address(udp_sock, host, datastore['RPORT']) || host

      @external_ports.each_index do |i|
        external_port = @external_ports[i]
        internal_port = @internal_ports[i]

        actual_ext_port = map_port(udp_sock, host, datastore['RPORT'], internal_port, external_port, Rex::Proto::NATPMP.const_get(protocol), lifetime)
        map_target = Rex::Socket.source_address(host)
        requested_forwarding = "#{external_address}:#{external_port}/#{protocol}" +
                              " -> " +
                              "#{map_target}:#{internal_port}/#{protocol}"
        if actual_ext_port
          map_target = datastore['CHOST'] ? datastore['CHOST'] : Rex::Socket.source_address(host)
          actual_forwarding = "#{external_address}:#{actual_ext_port}/#{protocol}" +
                                " -> " +
                                "#{map_target}:#{internal_port}/#{protocol}"
          if external_port == 0
            print_good("#{actual_forwarding} forwarded")
          else
            if (external_port != 0 && external_port != actual_ext_port)
              print_good("#{requested_forwarding} could not be forwarded, but #{actual_forwarding} could")
            else
              print_good("#{requested_forwarding} forwarded")
            end
          end
        else
          print_error("#{requested_forwarding} could not be forwarded")
        end

        report_service(
          :host   => host,
          :port   => datastore['RPORT'],
          :proto  => 'udp',
          :name  => 'natpmp',
          :state => Msf::ServiceState::Open
        )
      end
    rescue ::Interrupt
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
      nil
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e.backtrace}")
    end
  end
end
