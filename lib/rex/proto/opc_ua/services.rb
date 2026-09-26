# -*- coding: binary -*-
# frozen_string_literal: true

require 'bindata'
# BinData resolves field types when a record's class body is evaluated, so the
# library types have to be registered before the records below are defined.
# Under Zeitwerk they would otherwise not load until first referenced.
require 'rex/proto/opc_ua/types'

# The service layer: the structures every OPC-UA service request and response is
# built from, independent of the channel they travel on.
#
# The headers here are shared by every service, which is why they live at this
# level rather than with the SecureChannel services that were the first to need
# them. A service that never opens a channel of its own still sends a
# RequestHeader.
#
# Field order throughout is taken from reference/opcua/Opc.Ua.Types.bsd, the OPC
# Foundation's own machine-readable type definitions, rather than inferred from
# a capture. Each record names the StructuredType it was checked against.
module Rex::Proto::OpcUa::Services
  # The header every service request opens with.
  #
  # See OPC-UA Specification Part 4, section 7.32, Table 171, and the
  # RequestHeader StructuredType in reference/opcua/Opc.Ua.Types.bsd, which
  # gives the seven fields below in this order.
  #
  # ReturnDiagnostics is sent as zero throughout this library, which is what
  # entitles Rex::Proto::OpcUa::Types::OpcUaDiagnosticInfo to model only the
  # empty form of the diagnostics a response carries back.
  class RequestHeader < BinData::Record
    endian :little

    # The AuthenticationToken of a request sent without a session is the null
    # NodeId. That is also the default, so a RequestHeader built here is already
    # sessionless.
    opc_ua_node_id          :authentication_token
    opc_ua_date_time        :timestamp
    uint32                  :request_handle
    uint32                  :return_diagnostics
    opc_ua_string           :audit_entry_id
    uint32                  :timeout_hint
    opc_ua_extension_object :additional_header
  end

  # The header every service response opens with.
  #
  # See OPC-UA Specification Part 4, section 7.33, Table 172, and the
  # ResponseHeader StructuredType in reference/opcua/Opc.Ua.Types.bsd. The
  # schema splits the
  # StringTable into a NoOfStringTable Int32 and the elements it counts, which
  # is the ordinary OPC-UA array encoding that
  # Rex::Proto::OpcUa::Types::OpcUaArray implements.
  #
  # ServiceResult is the StatusCode for the service call itself, and is the
  # field that says whether the response body means anything: a service can fail
  # while the message carrying the failure is perfectly well formed.
  class ResponseHeader < BinData::Record
    endian :little

    opc_ua_date_time        :timestamp
    uint32                  :request_handle
    uint32                  :service_result
    opc_ua_diagnostic_info  :service_diagnostics
    opc_ua_array            :string_table, type: :opc_ua_string
    opc_ua_extension_object :additional_header
  end

  # Defensive ceilings on the arrays a GetEndpoints response carries.
  #
  # These bound allocation, and the number that matters is the product rather
  # than any one of them: every ceiling here sits inside the endpoint array, so
  # a server claiming the maximum everywhere costs MAX_ENDPOINTS multiplied by
  # the inner ceiling. Leaving the inner arrays on the 512 element default of
  # Rex::Proto::OpcUa::Types::OpcUaArray would allow 32768 UserTokenPolicy
  # objects, each of them five length prefixed strings, from one response.
  #
  # MAX_ENDPOINTS is carried over unchanged from the module this library
  # replaces. The two inner ceilings are set to match it: one number to reason
  # about, and each is more than ten times the largest count in any capture,
  # where the busiest endpoint advertises five token policies.
  MAX_ENDPOINTS = 64
  MAX_USER_TOKENS = 64
  MAX_DISCOVERY_URLS = 64

  # ApplicationDescription, the server's description of itself. See OPC-UA
  # Specification Part 4, section 7.2, Table 109, and the
  # ApplicationDescription StructuredType in reference/opcua/Opc.Ua.Types.bsd.
  #
  # ApplicationUri and ProductUri are the fingerprint worth reporting: they name
  # the product and installation rather than the host that answered.
  class ApplicationDescription < BinData::Record
    endian :little

    opc_ua_string         :application_uri
    opc_ua_string         :product_uri
    opc_ua_localized_text :application_name
    # ApplicationType: Server 0, Client 1, ClientAndServer 2, DiscoveryServer 3.
    # See OPC-UA Specification Part 4, section 7.4, Table 111, and the
    # enumeration of that name in reference/opcua/Opc.Ua.Types.bsd.
    uint32                :application_type
    opc_ua_string         :gateway_server_uri
    opc_ua_string         :discovery_profile_uri
    opc_ua_array          :discovery_urls, type: :opc_ua_string, max_length: MAX_DISCOVERY_URLS
  end

  # UserTokenPolicy, one way of proving identity that an endpoint will accept.
  # See OPC-UA Specification Part 4, section 7.41, Table 192, and the
  # UserTokenPolicy StructuredType in reference/opcua/Opc.Ua.Types.bsd.
  #
  # TokenType is a UserTokenType; see Rex::Proto::OpcUa::Enums::TOKEN_TYPES. A
  # policy of type Anonymous is the one that makes an endpoint reachable without
  # credentials at all.
  #
  # SecurityPolicyUri here is per token and is not the endpoint's own security
  # policy; a token may name a stronger one than the channel it arrives on.
  class UserTokenPolicy < BinData::Record
    endian :little

    opc_ua_string :policy_id
    uint32        :token_type
    opc_ua_string :issued_token_type
    opc_ua_string :issuer_endpoint_url
    opc_ua_string :security_policy_uri
  end

  # EndpointDescription, one way of connecting to a server. See OPC-UA
  # Specification Part 4, section 7.14, Table 135, and the EndpointDescription
  # StructuredType in reference/opcua/Opc.Ua.Types.bsd.
  #
  # SecurityMode is a MessageSecurityMode; see
  # Rex::Proto::OpcUa::Enums::SECURITY_MODES. The pair that matters to a scan is
  # a SecurityMode of None with an Anonymous UserIdentityToken, which together
  # mean an unauthenticated client can read process data over a channel nothing
  # is protecting.
  class EndpointDescription < BinData::Record
    endian :little

    opc_ua_string           :endpoint_url
    application_description :server
    opc_ua_byte_string      :server_certificate
    uint32                  :security_mode
    opc_ua_string           :security_policy_uri
    opc_ua_array            :user_identity_tokens, type: :user_token_policy, max_length: MAX_USER_TOKENS
    opc_ua_string           :transport_profile_uri
    uint8                   :security_level
  end

  # GetEndpointsRequest. See the GetEndpoints service in OPC-UA Specification
  # Part 4, section 5.5.4, and the GetEndpointsRequest StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd.
  #
  # The specification requires this service to be available without
  # authentication, so that a client can discover how it is expected to connect
  # before it has any way of connecting. That is what makes it enumerable.
  #
  # Both arrays are filters. They default to null rather than empty, which is
  # what asks for everything and what the module this library replaces sends;
  # an empty array encodes as a count of 0 and is a different request on the
  # wire.
  class GetEndpointsRequest < BinData::Record
    endian :little

    request_header :request_header
    opc_ua_string  :endpoint_url
    opc_ua_array   :locale_ids, type: :opc_ua_string, null_default: true
    opc_ua_array   :profile_uris, type: :opc_ua_string, null_default: true
  end

  # GetEndpointsResponse. See OPC-UA Specification Part 4, section 5.5.4, and
  # the GetEndpointsResponse StructuredType in
  # reference/opcua/Opc.Ua.Types.bsd.
  #
  # The endpoint array carries an explicit ceiling rather than the OpcUaArray
  # default; see MAX_ENDPOINTS above for why the inner arrays are capped too.
  class GetEndpointsResponse < BinData::Record
    endian :little

    response_header :response_header
    opc_ua_array    :endpoints, type: :endpoint_description, max_length: MAX_ENDPOINTS
  end
end
