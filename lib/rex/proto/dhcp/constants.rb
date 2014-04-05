# -*- coding: binary -*-
require 'rex/proto/dhcp'

module Rex
module Proto
module DHCP

Request = 1
Response = 2

DHCPDiscover = 1
DHCPOffer = 2
DHCPRequest = 3
DHCPAck = 5

DHCPMagic = "\x63\x82\x53\x63"

OpDHCPServer = 0x36
OpLeaseTime = 0x33
OpSubnetMask = 1
OpRouter = 3
OpDns = 6
OpHostname = 0x0c
OpEnd = 0xff

PXEMagic = "\xF1\x00\x74\x7E"
OpPXEMagic = 0xD0
OpPXEConfigFile = 0xD1
OpPXEPathPrefix = 0xD2
OpPXERebootTime = 0xD3

end
end
end
