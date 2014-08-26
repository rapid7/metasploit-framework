##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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
        OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-1000"]),
        OptEnum.new('PROTOCOL', [true, "Protocol to scan", 'TCP', %w(TCP UDP)]),
      ], self.class)
  end

  def run_host(host)
    begin
      udp_sock = Rex::Socket::Udp.create({
        'LocalHost' => datastore['CHOST'] || nil,
        'Context'   => {'Msf' => framework, 'MsfExploit' => self} }
      )
      add_socket(udp_sock)
      peer = "#{host}:#{datastore['RPORT']}"
      vprint_status("#{peer} Scanning #{datastore['PROTOCOL']} ports #{datastore['PORTS']} using NATPMP")

      # first, send a request to get the external address
      udp_sock.sendto(external_address_request, host, datastore['RPORT'], 0)
      external_address = nil
      while (r = udp_sock.recvfrom(12, 0.25) and r[1])
        (ver,op,result,epoch,external_address) = parse_external_address_response(r[0])
      end

      if (external_address)
        print_good("#{peer} responded with external address of #{external_address}")
      else
        vprint_status("#{peer} didn't respond with an external address")
        return
      end

      Rex::Socket.portspec_crack(datastore['PORTS']).each do |port|
        # send one request to clear the mapping if *we've* created it before
        clear_req = map_port_request(port, port, Rex::Proto::NATPMP.const_get(datastore['PROTOCOL']), 0)
        udp_sock.sendto(clear_req, host, datastore['RPORT'], 0)
        while (r = udp_sock.recvfrom(16, 1.0) and r[1])
        end

        # now try the real mapping
        map_req = map_port_request(port, port, Rex::Proto::NATPMP.const_get(datastore['PROTOCOL']), 1)
        udp_sock.sendto(map_req, host, datastore['RPORT'], 0)
        while (r = udp_sock.recvfrom(16, 1.0) and r[1])
          handle_reply(host, external_address, r)
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
      else
        state = Msf::ServiceState::Closed
        print_status("#{peer} #{external_addr} - #{int}/#{protocol} #{state} because of successful mapping with matched ports") if (datastore['DEBUG'])
      end
    else
      state = Msf::ServiceState::Closed
      print_status("#{peer} #{external_addr} - #{int}/#{protocol} #{state} because of code #{result} response") if (datastore['DEBUG'])
    end

    if inside_workspace_boundary?(external_addr)
      report_service(
        :host   => external_addr,
        :port   => int,
        :proto  => protocol,
        :state => state
      )
    end

    report_service(
      :host 	=> host,
      :port 	=> pkt[2],
      :name 	=> 'natpmp',
      :proto 	=> 'udp',
      :state	=> Msf::ServiceState::Open
    )
  end
end
