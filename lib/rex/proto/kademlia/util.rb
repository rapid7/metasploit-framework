# -*- coding: binary -*-

module Rex
module Proto
module Kademlia
  # Decodes an on-the-wire representation of a Kademlia peer to its 16-character hex equivalent
  #
  # @param bytes [String] the on-the-wire representation of a Kademlia peer
  # @return [String] the peer ID if valid, nil otherwise
  def self.decode_peer_id(bytes)
    peer_id = 0
    return nil unless bytes.size == 16
    bytes.unpack('VVVV').map { |p| peer_id = ((peer_id << 32) ^ p) }
    peer_id.to_s(16).upcase
  end

  # TODO
  # def encode_peer_id(id)
  # end
end
end
end
