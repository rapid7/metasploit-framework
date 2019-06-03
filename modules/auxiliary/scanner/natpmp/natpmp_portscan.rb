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
      'Name'        => 'NAT-PMP External Port Scanner',
      'Description' => 'Scan NAT devices for their external listening ports using NAT-PMP',
      'Author'      => 'Jon Hart <jhart[at]spoofed.org>',
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-1000"])
      ])
  end

  def run_host(host)
    begin
      udp_sock = Rex::Socket::Udp.create({
        'LocalHost' => datastore['CHOST'] || nil,
        'Context'   => {'Msf' => framework, 'MsfExploit' => self} }
      )
      add_socket(udp_sock)
      peer = "#{host}:#{datastore['RPORT']}"
      vprint_status("#{peer} Scanning #{protocol} ports #{datastore['PORTS']} using NATPMP")

      external_address = get_external_address(udp_sock, host, datastore['RPORT'])
      if (external_address)
        print_good("#{peer} responded with external address of #{external_address}")
      else
        vprint_status("#{peer} didn't respond with an external address")
        return
      end

      # clear all mappings
      map_port(udp_sock, host, datastore['RPORT'], 0, 0, Rex::Proto::NATPMP.const_get(protocol), 0)

      Rex::Socket.portspec_crack(datastore['PORTS']).each do |port|
        map_req = map_port_request(port, port, Rex::Proto::NATPMP.const_get(datastore['PROTOCOL']), 1)
        udp_sock.sendto(map_req, host, datastore['RPORT'], 0)
        while (r = udp_sock.recvfrom(16, 1.0) and r[1])
          break if handle_reply(host, external_address, r)
        end
      end

    rescue ::Interrupt
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
      nil
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e.backtrace}")
    end
  end

  def handle_reply(host, external_addr, pkt)
    return if not pkt[1]

    if(pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end
    host = pkt[1]
    protocol = datastore['PROTOCOL'].to_s.downcase

    (ver, op, result, epoch, int, ext, lifetime) = parse_map_port_response(pkt[0])
    peer = "#{host}:#{datastore['RPORT']}"
    if (result == 0)
      # we always ask to map an external port to the same port on us.  If
      # we get a successful reponse back but the port we requested be forwarded
      # is different, that means that someone else already has it open
      if (int != ext)
        state = Msf::ServiceState::Open
        print_good("#{peer} #{external_addr} - #{int}/#{protocol} #{state} because of successful mapping with unmatched ports")
        if inside_workspace_boundary?(external_addr)
          report_service(
            :host   => external_addr,
            :port   => int,
            :proto  => protocol,
            :state => state
          )
        end
      else
        state = Msf::ServiceState::Closed
        vprint_error("#{peer} #{external_addr} - #{int}/#{protocol} #{state} because of successful mapping with matched ports")
      end
    else
      state = Msf::ServiceState::Closed
      vprint_error("#{peer} #{external_addr} - #{int}/#{protocol} #{state} because of code #{result} response")
    end

    report_service(
      :host 	=> host,
      :port 	=> pkt[2],
      :name 	=> 'natpmp',
      :proto 	=> 'udp',
      :state	=> Msf::ServiceState::Open
    )
    true
  end
end
