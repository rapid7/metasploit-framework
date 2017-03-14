# -*- coding: binary -*-
##
#
# NAT-PMP protocol support
#
##

module Rex
module Proto
module NATPMP

  # Return a NAT-PMP request to get the external address.
  def external_address_request
    [ 0, 0 ].pack('nn')
  end

  def get_external_address(udp_sock, host, port, timeout=1)
    vprint_status("#{host}:#{port} - Probing NAT-PMP for external address")
    udp_sock.sendto(external_address_request, host, port, 0)
    external_address = nil
    while (r = udp_sock.recvfrom(12, timeout) and r[1])
      (ver, op, result, epoch, external_address) = parse_external_address_response(r[0])
      if external_address
        vprint_good("#{host}:#{port} - NAT-PMP external address is #{external_address}")
        break
      end
    end
    external_address
  end

  # Parse a NAT-PMP external address response +resp+.
  # Returns the decoded parts of the response as an array.
  def parse_external_address_response(resp)
    (ver, op, result, epoch, addr) = resp.unpack("CCnNN")
    [ ver, op, result, epoch, Rex::Socket::addr_itoa(addr) ]
  end

  def map_port(udp_sock, host, port, int_port, ext_port, protocol, lifetime, timeout=1)
    vprint_status("#{host}:#{port} - Sending NAT-PMP mapping request")
    # build the mapping request
    req = map_port_request(int_port, ext_port,
      Rex::Proto::NATPMP.const_get(datastore['PROTOCOL']), datastore['LIFETIME'])
    # send it
    udp_sock.sendto(req, host, datastore['RPORT'], 0)
    # handle the reply
    while (r = udp_sock.recvfrom(16, timeout) and r[1])
      (_, _, result, _, _, actual_ext_port, _) = parse_map_port_response(r[0])
      return (result == 0 ? actual_ext_port : nil)
    end
    nil
  end

  # Return a NAT-PMP request to map remote port +rport+/+protocol+ to local port +lport+ for +lifetime+ ms
  def map_port_request(lport, rport, protocol, lifetime)
    [ Rex::Proto::NATPMP::Version, # version
      protocol, # opcode, which is now the protocol we are asking to forward
      0, # reserved
      lport,
      rport,
      lifetime
    ].pack("CCnnnN")
  end

  # Parse a NAT-PMP mapping response +resp+.
  # Returns the decoded parts as an array.
  def parse_map_port_response(resp)
    resp.unpack("CCnNnnN")
  end

end

end
end
