# -*- coding: binary -*-

require 'rex/proto/kademlia/message'
require 'rex/proto/kademlia/util'

module Rex
module Proto
module Kademlia
  # Opcode for a bootstrap response
  BOOTSTRAP_RESPONSE = 0x09

  # A Kademlia bootstrap response message
  class BootstrapResponse < Message
    # @return [String] the ID of the peer that send the bootstrap response
    attr_reader :peer_id
    # @return [Integer] the TCP port that the responding peer is listening on
    attr_reader :tcp_port
    # @return [Integer] the version of this peer
    attr_reader :version
    # @return [Array<Hash<String, Object>>] the peer ID, IP address, UDP/TCP ports and version of each peer
    attr_reader :peers

    # Constructs a new bootstrap response
    #
    # @param peer_id [String] the ID of this peer
    # @param tcp_port [Integer] the TCP port that this peer is listening on
    # @param version [Integer] the version of this peer
    # @param peers [Array<Hash<String, Object>>] the peer ID, IP address, UDP/TCP ports and version of each peer
    def initialize(peer_id, tcp_port, version, peers)
      @peer_id = peer_id
      @tcp_port = tcp_port
      @version = version
      @peers = peers
    end

    # The minimum size of a peer in a KADEMLIA2_BOOTSTRAP_RES message:
    # peer ID (16-bytes), IP (4 bytes), UDP port (2 bytes), TCP port (2 bytes)
    # and version (1 byte)
    BOOTSTRAP_PEER_SIZE = 25

    # Builds a bootstrap response from given data
    #
    # @param data [String] the data to decode
    # @return [BootstrapResponse] the bootstrap response if the data is valid, nil otherwise
    def self.from_data(data)
      message = Message.from_data(data)
      # abort if this isn't a valid response
      return unless message
      return unless message.type == BOOTSTRAP_RESPONSE
      return unless message.body.size >= 23
      bootstrap_peer_id = Rex::Proto::Kademlia.decode_peer_id(message.body.slice!(0, 16))
      bootstrap_tcp_port, bootstrap_version, num_peers = message.body.slice!(0, 5).unpack('vCv')
      # protocol says there are no peers and the body confirms this, so just return with no peers
      if num_peers == 0 && message.body.to_s.strip.empty?
        peers = []
      else
        peers_data = message.body
        # peers data is too long/short, abort
        return if peers_data.size % BOOTSTRAP_PEER_SIZE != 0
        peers = []
        until peers_data.to_s.strip.empty?
          peer_data = peers_data.slice!(0, BOOTSTRAP_PEER_SIZE)
          peer_id = Rex::Proto::Kademlia.decode_peer_id(peer_data.slice!(0, 16))
          ip, udp_port, tcp_port, version = peer_data.unpack('VvvC')
          peers << {
            id: peer_id,
            ip: Rex::Socket.addr_itoa(ip),
            tcp_port: tcp_port,
            udp_port: udp_port,
            version: version
          }
        end
      end
      BootstrapResponse.new(bootstrap_peer_id, bootstrap_tcp_port, bootstrap_version, peers)
    end
  end
end
end
end
