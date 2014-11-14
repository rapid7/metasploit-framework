# -*- coding: binary -*-

module Rex
module Proto
##
#
# Minimal support for the newer Kademlia protocol, referred to here and often
# elsewhere as Kademlia2.  It is unclear how this differs from the old protocol.
#
# Protocol details are hard to come by because most documentation is academic
# in nature and glosses over the low-level network details.  The best
# documents I found on the protocol are:
#
# http://gbmaster.wordpress.com/2013/05/05/botnets-surrounding-us-an-initial-focus-on-kad/
# http://gbmaster.wordpress.com/2013/06/16/botnets-surrounding-us-sending-kademlia2_bootstrap_req-kademlia2_hello_req-and-their-strict-cousins/
# http://gbmaster.wordpress.com/2013/11/23/botnets-surrounding-us-performing-requests-sending-out-kademlia2_req-and-asking-contact-where-art-thou/
#
##
module Kademlia
  STANDARD_PACKET = 0xE4
  # TODO: support this format
  COMPRESSED_PACKET = 0xE5

  BOOTSTRAP_REQ = 0x01
  BOOTSTRAP_RES = 0x09
  PING = 0x60
  PONG = 0x61

  # The minimum size of a peer in a KADEMLIA2_BOOTSTRAP_RES message:
  # peer ID (16-bytes), IP (4 bytes), UDP port (2 bytes), TCP port (2 bytes)
  # and version (1 byte)
  BOOTSTRAP_PEER_SIZE = 25

  def decode_message(message)
    # minimum size is header (1) + opcode (1) + stuff (0+)
    return if message.length < 2
    header, opcode = message.unpack('CC')
    if header == COMPRESSED_PACKET
      fail NotImplementedError, "Unable to handle compressed #{message.length}-byte compressed Kademlia message"
    end
    return if header != STANDARD_PACKET
    [opcode, message[2, message.length]]
  end

  def encode_message(type, payload = '')
    [STANDARD_PACKET, type].pack('CC') + payload
  end

  def bootstrap
    encode_message(BOOTSTRAP_REQ)
  end

  def decode_bootstrap_res(message)
    opcode, payload = decode_message(message)
    # abort if this isn't a valid response
    return nil unless opcode = BOOTSTRAP_RES
    return nil unless payload.size >= 23
    peer_id = decode_peer_id(payload.slice!(0,16))
    tcp_port, version, num_peers = payload.slice!(0,5).unpack('vCv')
    # protocol says there are no peers and the payload confirms this, so just return with no peers
    return [ tcp_port, version, []] if num_peers == 0 && payload.blank?
    peers = decode_bootstrap_peers(payload)
    # abort if the peer data was invalid
    return nil unless peers
    [ peer_id, tcp_port, version, peers ]
  end

  # Returns a PING message
  def ping
    encode_message(PING)
  end

  # Decodes a PONG message, returning the port used by the peer
  def decode_pong(message)
    opcode, port = decode_message(message)
    # abort if this isn't a pong
    return nil unless opcode == PONG
    # abort if the response is too large/small
    return nil unless port && port.size == 2
    # this should always be equivalent to the source port from which the PING was received
    port.unpack('v')[0]
  end

  def decode_bootstrap_peers(peers_data)
    # sanity check total size
    return nil unless peers_data.size % BOOTSTRAP_PEER_SIZE == 0
    peers = []
    until peers_data.blank?
      peers << decode_bootstrap_peer(peers_data.slice!(0, BOOTSTRAP_PEER_SIZE))
    end
    peers
  end

  def decode_bootstrap_peer(peer_data)
    # sanity check the size of this peer's data
    return nil unless peer_data.size == BOOTSTRAP_PEER_SIZE
    # TODO; interpret this properly
    peer_id = peer_data.slice!(0, 16)
    ip, udp_port, tcp_port, version = peer_data.unpack('VvvC')
    [ decode_peer_id(peer_id), Rex::Socket.addr_itoa(ip), udp_port, tcp_port, version ]
  end


  def decode_peer_id(bytes)
    peer_id = 0
    return nil unless bytes.size == 16
    bytes.unpack('VVVV').map { |p| peer_id <<= 32; peer_id ^= p; }
    peer_id.to_s(16).upcase
  end

  # TODO?
  def encode_peer_id(id)
  end
end
end
end