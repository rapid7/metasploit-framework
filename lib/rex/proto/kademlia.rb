# -*- coding: binary -*-

module Rex::Proto::Kademlia
  # Decodes an on-the-wire representation of a Kademlia peer to its 16-character hex equivalent
  #
  # @deprecated Access via Rex::Proto::Kademlia::Util
  # @param bytes [String] the on-the-wire representation of a Kademlia peer
  # @return [String] the peer ID if valid, nil otherwise
  def self.decode_peer_id(bytes)
    Util.decode_peer_id(bytes)
  end
end
