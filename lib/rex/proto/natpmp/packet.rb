# -*- coding: binary -*-
##
#
# NAT-PMP protocol support
#
# by Jon Hart <jhart@spoofed.org>
#
##

module Rex
module Proto
module NATPMP

  # Return a NAT-PMP request to get the external address.
  def self.external_address_request
    [ 0, 0 ].pack('nn')
  end

  # Parse a NAT-PMP external address response +resp+.
  # Returns the decoded parts of the response as an array.
  def self.parse_external_address_response(resp)
    (ver, op, result, epoch, addr) = resp.unpack("CCSLN")
    [ ver, op, result, epoch, Rex::Socket::addr_itoa(addr) ]
  end

  # Return a NAT-PMP request to map remote port +rport+/+protocol+ to local port +lport+ for +lifetime+ ms
  def self.map_port_request(lport, rport, protocol, lifetime)
    [   Rex::Proto::NATPMP::Version, # version
      protocol, # opcode, which is now the protocol we are asking to forward
      0, # reserved
      lport,
      rport,
      lifetime
    ].pack("ccnnnN")
  end

  # Parse a NAT-PMP mapping response +resp+.
  # Returns the decoded parts as an array.
  def self.parse_map_port_response(resp)
    resp.unpack("CCSLnnN")
  end
end

end
end
