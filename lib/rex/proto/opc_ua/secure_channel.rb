# -*- coding: binary -*-
# frozen_string_literal: true

require 'bindata'
# BinData resolves field types when a record's class body is evaluated, so the
# library types and the shared service headers have to be registered before the
# records below are defined. Under Zeitwerk they would otherwise not load until
# first referenced.
require 'rex/proto/opc_ua/types'
require 'rex/proto/opc_ua/services'

# The SecureChannel layer: the headers that wrap every message on a channel, and
# the services that open and close one.
#
# A channel is opened with OpenSecureChannel and identified from then on by the
# SecureChannelId and TokenId it returns. Under SecurityPolicy None nothing here
# is signed or encrypted, so the headers are the whole of the security layer as
# far as this library is concerned.
#
# The service records hold the service structures alone. The TypeId NodeId that
# precedes one in a message is part of the message encoding rather than part of
# the service, and is read and written separately.
#
# Field order throughout is taken from reference/opcua/Opc.Ua.Types.bsd rather
# than inferred from a capture. Each record names the StructuredType it was
# checked against, and every one of them was also walked byte for byte through
# spec/file_fixtures/opc_ua/open_secure_channel_response_node_opcua.bin.
module Rex::Proto::OpcUa::SecureChannel
  # The security header of an OPN message, carrying the policy the channel is
  # being opened under and the certificates that policy needs.
  #
  # See Table 58 in OPC-UA Specification Part 6, section 6.7.2.3, which names
  # the three fields in this order, each as a length prefixed pair. It is not a
  # StructuredType in reference/opcua/Opc.Ua.Types.bsd, which describes the
  # service structures rather than the channel framing that carries them.
  #
  # Under SecurityPolicy None both certificate fields are null, which is what
  # makes an OPN exchange readable on the wire and lets a client open a channel
  # with no key material of its own.
  class AsymmetricSecurityHeader < BinData::Record
    endian :little

    opc_ua_string      :security_policy_uri
    opc_ua_byte_string :sender_certificate
    opc_ua_byte_string :receiver_certificate_thumbprint
  end

  # The security header of every message sent on an open channel, naming the
  # token the message is secured with. This is the whole of it: a single UInt32.
  #
  # Defined in OPC-UA Specification Part 6, section 6.7.2.3, the same section as
  # the asymmetric header above; the two are alternatives chosen by the type of
  # security applied to the message. Its table follows Table 58 there and is the
  # one uncaptioned table in the section, so it is cited by section rather than
  # by number. Like the asymmetric header, this is channel framing rather than a
  # StructuredType in the schema.
  #
  # A MSG chunk carries the SecureChannelId, then this, then a SequenceHeader
  # ahead of its slice of the payload, which is the 16 bytes that
  # Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN accounts for.
  class SymmetricSecurityHeader < BinData::Record
    endian :little

    uint32 :token_id
  end

  # Follows the security header of every message. The RequestId is what pairs a
  # response with the request that asked for it.
  #
  # See Table 60 in OPC-UA Specification Part 6, section 6.7.2.4.
  class SequenceHeader < BinData::Record
    endian :little

    uint32 :sequence_number
    uint32 :request_id
  end

  # The token an OpenSecureChannel response issues. ChannelId and TokenId are
  # what subsequent messages quote; CreatedAt and RevisedLifetime say when the
  # server will stop honoring them, the revised lifetime being the server's
  # answer to the lifetime the client asked for rather than the client's request
  # granted.
  #
  # ChannelSecurityToken has no section of its own in OPC-UA Specification
  # Part 4: it is defined inline among the OpenSecureChannel response parameters
  # in section 5.6.2.2. See also the ChannelSecurityToken StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd, which gives the four fields in this
  # order.
  class ChannelSecurityToken < BinData::Record
    endian :little

    uint32           :channel_id
    uint32           :token_id
    opc_ua_date_time :created_at
    uint32           :revised_lifetime
  end

  # The body of a MSG or CLO message sent on an open channel: the
  # SecureChannelId and TokenId the server issued, a SequenceHeader, and then
  # the already encoded request.
  #
  # This is the write side of the same framing #parse_open_response walks on the
  # way in, in its symmetric form: an OPN carries an AsymmetricSecurityHeader
  # here instead, because the channel it opens does not exist yet. The three
  # headers come to the 16 bytes Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN
  # accounts for when it reassembles a chunked response.
  #
  # Under SecurityPolicy None nothing is signed or encrypted, so quoting the
  # token back is the whole of what the channel asks of a message on it.
  #
  # @param token [ChannelSecurityToken] the token the OpenSecureChannel
  #   response issued.
  # @param sequence [Integer] the SequenceNumber and RequestId for this message.
  #   The two are given the same value, which is legal and keeps a response
  #   pairable with the request that asked for it.
  # @param request [String] the service TypeId followed by the encoded service
  #   request.
  # @return [String] the message body, ready for
  #   Rex::Proto::OpcUa::Tcp::MessageStream#send_message.
  def self.symmetric_body(token, sequence, request)
    body = [token.channel_id.snapshot].pack('V')
    body << SymmetricSecurityHeader.new(token_id: token.token_id.snapshot).to_binary_s
    body << SequenceHeader.new(sequence_number: sequence, request_id: sequence).to_binary_s
    body << request
    body
  end

  # OpenSecureChannelRequest.
  #
  # See OPC-UA Specification Part 4, section 5.6.2, and the
  # OpenSecureChannelRequest StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd.
  #
  # RequestType is a SecurityTokenRequestType and SecurityMode a
  # MessageSecurityMode; for the latter see
  # Rex::Proto::OpcUa::Enums::SECURITY_MODES. Under the None policy the
  # ClientNonce is null rather than empty, since there is no key material to
  # derive.
  class OpenSecureChannelRequest < BinData::Record
    endian :little

    # SecurityTokenRequestType, from the enumeration of the same name in
    # reference/opcua/Opc.Ua.Types.bsd.
    ISSUE = 0
    RENEW = 1

    request_header     :request_header
    uint32             :client_protocol_version
    uint32             :request_type
    uint32             :security_mode
    opc_ua_byte_string :client_nonce
    uint32             :requested_lifetime
  end

  # OpenSecureChannelResponse.
  #
  # See OPC-UA Specification Part 4, section 5.6.2, and the
  # OpenSecureChannelResponse StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd.
  #
  # The ServerNonce pairs with the ClientNonce and is null under the None
  # policy. Reading it is what makes the record account for the whole response
  # rather than stopping at the last field the caller happens to want.
  class OpenSecureChannelResponse < BinData::Record
    endian :little

    response_header        :response_header
    uint32                 :server_protocol_version
    channel_security_token :security_token
    opc_ua_byte_string     :server_nonce
  end

  # Decode the body of an OPN message, which is everything the transport hands
  # back after the 8 byte message header.
  #
  # An OPN body is framed as a plaintext SecureChannelId, an
  # AsymmetricSecurityHeader, a SequenceHeader and the TypeId naming the
  # service, and only then the service structure. The lengths of the first three
  # depend on their contents, so they have to be walked rather than skipped.
  #
  # The envelope is identical for a request and a response, and what follows the
  # TypeId is decided by that TypeId, so this reads the response form the caller
  # asked for rather than dispatching on it.
  #
  # @param body [String] the OPN message body.
  # @return [OpenSecureChannelResponse]
  # @raise [BinData::ValidityError] if a record along the way will not decode.
  # @raise [IOError] if the body is shorter than the framing it declares.
  def self.parse_open_response(body)
    raw = body.to_s.b
    offset = 4 # SecureChannelId

    [AsymmetricSecurityHeader, SequenceHeader, Rex::Proto::OpcUa::Types::OpcUaNodeId].each do |record|
      offset += record.read(raw.byteslice(offset..-1).to_s).num_bytes
    end

    OpenSecureChannelResponse.read(raw.byteslice(offset..-1).to_s)
  end

  # CloseSecureChannelRequest. The channel being closed is the one the message
  # is sent on, so the request carries nothing beyond its header.
  #
  # See OPC-UA Specification Part 4, section 5.6.3, and the
  # CloseSecureChannelRequest StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd, which is a RequestHeader and nothing else.
  class CloseSecureChannelRequest < BinData::Record
    endian :little

    request_header :request_header
  end
end
