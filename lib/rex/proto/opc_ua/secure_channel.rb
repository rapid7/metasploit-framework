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
  # See OPC-UA Specification Part 6, section 6.7.2, which names the three fields
  # of the AsymmetricAlgorithmSecurityHeader in this order. It is not a
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
  # See OPC-UA Specification Part 6, section 6.7.2, for the
  # SymmetricAlgorithmSecurityHeader. Like the asymmetric header above it is
  # channel framing rather than a StructuredType in the schema.
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
  # See OPC-UA Specification Part 6, section 6.7.2, for the SequenceHeader.
  class SequenceHeader < BinData::Record
    endian :little

    uint32 :sequence_number
    uint32 :request_id
  end

  # The token an OpenSecureChannel response issues. ChannelId and TokenId are
  # what subsequent messages quote; CreatedAt and RevisedLifetime say when the
  # server will stop honouring them, the revised lifetime being the server's
  # answer to the lifetime the client asked for rather than the client's request
  # granted.
  #
  # See OPC-UA Specification Part 4, section 7.6, and the ChannelSecurityToken
  # StructuredType in reference/opcua/Opc.Ua.Types.bsd.
  class ChannelSecurityToken < BinData::Record
    endian :little

    uint32           :channel_id
    uint32           :token_id
    opc_ua_date_time :created_at
    uint32           :revised_lifetime
  end

  # OpenSecureChannelRequest.
  #
  # See OPC-UA Specification Part 4, section 5.5.2, and the
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
  # See OPC-UA Specification Part 4, section 5.5.2, and the
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

  # CloseSecureChannelRequest. The channel being closed is the one the message
  # is sent on, so the request carries nothing beyond its header.
  #
  # See OPC-UA Specification Part 4, section 5.5.3, and the
  # CloseSecureChannelRequest StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd, which is a RequestHeader and nothing else.
  class CloseSecureChannelRequest < BinData::Record
    endian :little

    request_header :request_header
  end
end
