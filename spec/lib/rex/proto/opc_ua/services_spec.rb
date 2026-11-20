# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/opc_ua/services'

RSpec.describe 'Rex::Proto::OpcUa::Services' do
  # The headers here are exercised against the OpenSecureChannelResponse
  # capture, which is the smallest captured message that carries a complete
  # ResponseHeader. That the header belongs to a SecureChannel service is
  # incidental: it is the same header every service uses, which is the reason it
  # lives at this level. See spec/file_fixtures/opc_ua/README.md for provenance.
  let(:response) do
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'open_secure_channel_response_node_opcua.bin'))
  end

  # The ResponseHeader begins after the message header, the SecureChannelId, the
  # asymmetric security header, the SequenceHeader and the TypeId. The offset
  # was established by walking the response field by field; the walk consumes
  # the message exactly, which secure_channel_spec.rb asserts.
  let(:response_header_offset) { 0x53 }

  describe Rex::Proto::OpcUa::Services::ResponseHeader do
    subject(:response_header) { described_class.read(response[response_header_offset..]) }

    it 'decodes the Timestamp' do
      expect(response_header.timestamp.to_time).to eq ::Time.utc(2026, 8, 27, 0, 34, 59) + Rational(704, 1000)
    end

    it 'decodes the RequestHandle' do
      expect(response_header.request_handle.snapshot).to eq 1
    end

    # Zero is Good. A service can fail while the message carrying the failure is
    # perfectly well formed, so this is the field that says whether the rest of
    # the response means anything.
    it 'decodes the ServiceResult' do
      expect(response_header.service_result.snapshot).to eq 0
    end

    it 'decodes the ServiceDiagnostics as empty' do
      expect(response_header.service_diagnostics.snapshot)
        .to eq Rex::Proto::OpcUa::Types::OpcUaDiagnosticInfo::EMPTY
    end

    it 'decodes the StringTable as empty' do
      expect(response_header.string_table).to be_empty
    end

    # The server sent a count of zero, not the -1 that would mean null, and the
    # two re-encode differently.
    it 'decodes the StringTable as empty rather than null' do
      expect(response_header.string_table).not_to be_null
    end

    it 'decodes the AdditionalHeader as an empty ExtensionObject' do
      expect(response_header.additional_header.encoding.snapshot)
        .to eq Rex::Proto::OpcUa::Types::OpcUaExtensionObject::NO_BODY
    end

    it 'accounts for the bytes between the TypeId and the ServerProtocolVersion' do
      expect(response_header.num_bytes).to eq 24
    end

    it 're-encodes to the captured bytes' do
      expect(response_header.to_binary_s).to eq response.byteslice(response_header_offset, 24)
    end
  end

  describe Rex::Proto::OpcUa::Services::RequestHeader do
    # No capture contains a request; every message under
    # spec/file_fixtures/opc_ua is a server response. The expected bytes are
    # hand-built from the RequestHeader StructuredType in
    # reference/opcua/Opc.Ua.Types.bsd, and are what the shipped module builds
    # in build_request_header.
    subject(:request_header) do
      described_class.new(timestamp: 0, request_handle: 2, return_diagnostics: 0, timeout_hint: 10_000)
    end

    let(:expected) do
      [0x00, 0x00].pack('CC') +          # AuthenticationToken: null NodeId
        [0].pack('q<') +                 # Timestamp
        [2].pack('V') +                  # RequestHandle
        [0].pack('V') +                  # ReturnDiagnostics: none
        [-1].pack('l<') +                # AuditEntryId: null
        [10_000].pack('V') +             # TimeoutHint in milliseconds
        [0x00, 0x00, 0x00].pack('CCC')   # AdditionalHeader: null ExtensionObject
    end

    it 'encodes its seven fields in schema order' do
      expect(request_header.to_binary_s).to eq expected
    end

    # A sessionless request carries the null NodeId as its AuthenticationToken,
    # which is what GetEndpoints and OpenSecureChannel both send. Getting that
    # from the default is what lets a caller build one without naming it.
    it 'defaults the AuthenticationToken to the null NodeId' do
      expect(request_header.authentication_token.to_binary_s).to eq "\x00\x00".b
    end

    it 'defaults the AuditEntryId to null rather than empty' do
      expect(request_header.audit_entry_id.snapshot).to be_nil
    end

    it 'round trips' do
      expect(described_class.read(request_header.to_binary_s).snapshot).to eq request_header.snapshot
    end
  end

  # The GetEndpoints capture: a MSG message whose single F chunk carries the
  # response. See spec/file_fixtures/opc_ua/README.md for provenance.
  let(:get_endpoints) do
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'get_endpoints_response_node_opcua.bin'))
  end

  # What Rex::Proto::OpcUa::Tcp::MessageStream#recv_service_response hands back:
  # the message with its header and the secure conversation prefix removed, so
  # it begins at the response TypeId.
  let(:service_payload) do
    get_endpoints[(Rex::Proto::OpcUa::Tcp::HEADER_LEN + Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN)..]
  end

  let(:type_id) { Rex::Proto::OpcUa::Types::OpcUaNodeId.read(service_payload) }
  let(:get_endpoints_response) do
    Rex::Proto::OpcUa::Services::GetEndpointsResponse.read(service_payload[type_id.num_bytes..])
  end
  let(:endpoints) { get_endpoints_response.endpoints }

  describe 'the array ceilings' do
    # Carried over unchanged from the module this library replaces.
    it 'caps the endpoint array at 64' do
      expect(Rex::Proto::OpcUa::Services::MAX_ENDPOINTS).to eq 64
    end

    # The endpoint ceiling alone does not bound allocation, because each
    # endpoint carries arrays of its own. These are what stop the product
    # running away.
    it 'caps the user token array below the OpcUaArray default' do
      expect(Rex::Proto::OpcUa::Services::MAX_USER_TOKENS)
        .to be < Rex::Proto::OpcUa::Types::OpcUaArray::DEFAULT_MAX_LENGTH
    end

    it 'caps the discovery url array below the OpcUaArray default' do
      expect(Rex::Proto::OpcUa::Services::MAX_DISCOVERY_URLS)
        .to be < Rex::Proto::OpcUa::Types::OpcUaArray::DEFAULT_MAX_LENGTH
    end

    # Patching the count in the captured bytes is what proves the declaration
    # site carries the ceiling, rather than that OpcUaArray can enforce one.
    it 'rejects an endpoint count above the ceiling before reading any element' do
      body = get_endpoints_response.to_binary_s.dup
      body[get_endpoints_response.endpoints.rel_offset, 4] =
        [Rex::Proto::OpcUa::Services::MAX_ENDPOINTS + 1].pack('l<')

      expect { Rex::Proto::OpcUa::Services::GetEndpointsResponse.read(body).num_bytes }
        .to raise_error(BinData::ValidityError, /array length 65 exceeds the 64 element ceiling/)
    end

    it 'rejects a user token count above the ceiling' do
      endpoint = endpoints.first
      body = endpoint.to_binary_s.dup
      body[endpoint.user_identity_tokens.rel_offset, 4] =
        [Rex::Proto::OpcUa::Services::MAX_USER_TOKENS + 1].pack('l<')

      expect { Rex::Proto::OpcUa::Services::EndpointDescription.read(body).num_bytes }
        .to raise_error(BinData::ValidityError, /exceeds the 64 element ceiling for obj.user_identity_tokens/)
    end
  end

  describe Rex::Proto::OpcUa::Services::GetEndpointsResponse do
    it 'is identified by the response TypeId that precedes it' do
      expect(type_id.identifier).to eq Rex::Proto::OpcUa::Enums::NodeIds::GET_ENDPOINTS_RESPONSE
    end

    it 'decodes a successful ServiceResult' do
      expect(get_endpoints_response.response_header.service_result.snapshot).to eq 0
    end

    it 'decodes seven endpoints' do
      expect(endpoints.length).to eq 7
    end

    # The first endpoint advertises five token policies and the rest three. A
    # reader that lost its place inside one endpoint would still produce seven
    # of something, so the per-endpoint counts are what show the walk stayed
    # aligned across the whole array.
    it 'decodes the token policy count of every endpoint' do
      expect(endpoints.map { |ep| ep.user_identity_tokens.length }).to eq [5, 3, 3, 3, 3, 3, 3]
    end

    # This is the assertion the whole record layer exists to support: the
    # response is consumed exactly, so no field was skipped, none was counted
    # twice, and nothing was left dangling for the next read to trip over.
    it 'consumes the service payload with no bytes left over' do
      expect(type_id.num_bytes + get_endpoints_response.num_bytes).to eq service_payload.bytesize
    end

    it 're-encodes byte for byte to the captured payload' do
      expect(type_id.to_binary_s + get_endpoints_response.to_binary_s).to eq service_payload
    end

    it 'accounts for the whole 10648 byte capture once the framing is counted' do
      framing = Rex::Proto::OpcUa::Tcp::HEADER_LEN + Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN
      expect(framing + type_id.num_bytes + get_endpoints_response.num_bytes).to eq 10_648
    end
  end

  describe Rex::Proto::OpcUa::Services::EndpointDescription do
    subject(:endpoint) { endpoints.first }

    it 'decodes the EndpointUrl' do
      expect(endpoint.endpoint_url.snapshot).to eq 'opc.tcp://ua-node:4840/UA/BackdraftTest'
    end

    # Asserted across the whole array rather than for one endpoint: seven
    # distinct policies in the right order is what shows the walk stayed
    # aligned through seven variable length records, six of which carry a
    # server certificate of over a kilobyte.
    it 'decodes the SecurityPolicyUri of every endpoint' do
      expect(endpoints.map { |ep| Rex::Proto::OpcUa::Enums.security_policy_name(ep.security_policy_uri.snapshot) })
        .to eq %w[
          None
          Basic256Sha256
          Aes128_Sha256_RsaOaep
          Aes256_Sha256_RsaPss
          Basic256Sha256
          Aes128_Sha256_RsaOaep
          Aes256_Sha256_RsaPss
        ]
    end

    it 'decodes the MessageSecurityMode of every endpoint' do
      expect(endpoints.map { |ep| Rex::Proto::OpcUa::Enums.security_mode_name(ep.security_mode.snapshot) })
        .to eq %w[None Sign Sign Sign SignAndEncrypt SignAndEncrypt SignAndEncrypt]
    end

    it 'decodes the ServerCertificate as a ByteString rather than a String' do
      expect(endpoint.server_certificate.snapshot.encoding).to eq ::Encoding::BINARY
    end

    # SecurityLevel is the last field of the record, a single byte after a
    # length prefixed TransportProfileUri. Reading the right value for every
    # endpoint is what shows each record ended where the next one began.
    it 'decodes the SecurityLevel that follows the TransportProfileUri' do
      expect(endpoints.map { |ep| ep.security_level.snapshot }).to eq [1, 106, 105, 107, 206, 205, 207]
    end

    # The None/Anonymous endpoint is the finding this whole scanner exists to
    # report: no encryption on the channel and no credential required.
    it 'includes an endpoint offering MessageSecurityMode None' do
      none = endpoints.select { |ep| Rex::Proto::OpcUa::Enums.security_mode_name(ep.security_mode.snapshot) == 'None' }

      expect(none).not_to be_empty
    end

    it 'includes an endpoint accepting the Anonymous token over an unencrypted channel' do
      weak = endpoints.select do |ep|
        Rex::Proto::OpcUa::Enums.security_mode_name(ep.security_mode.snapshot) == 'None' &&
          ep.user_identity_tokens.any? { |token| token.token_type.snapshot.zero? }
      end

      expect(weak).not_to be_empty
    end
  end

  describe Rex::Proto::OpcUa::Services::ApplicationDescription do
    subject(:server) { endpoints.first.server }

    it 'decodes the ApplicationUri' do
      expect(server.application_uri.snapshot).to eq 'urn:ua-node:NodeOPCUA-Server'
    end

    it 'decodes the ProductUri' do
      expect(server.product_uri.snapshot).to eq 'NodeOPCUA-Server'
    end

    it 'decodes the ApplicationName as a LocalizedText' do
      expect(server.application_name.to_s).to eq 'NodeOPCUA'
    end

    # Server, from the ApplicationType enumeration in the schema.
    it 'decodes the ApplicationType' do
      expect(server.application_type.snapshot).to eq 0
    end

    it 'decodes the DiscoveryUrls array' do
      expect(server.discovery_urls.map(&:snapshot)).to all(be_a(String))
    end
  end

  describe Rex::Proto::OpcUa::Services::UserTokenPolicy do
    subject(:policies) { endpoints.first.user_identity_tokens }

    it 'decodes each PolicyId rather than only counting the elements' do
      expect(policies.map { |policy| policy.policy_id.snapshot }).to eq %w[
        username_basic256Sha256
        username_aes128Sha256RsaOaep
        certificate_basic256Sha256
        certificate_aes128Sha256RsaOaep
        anonymous
      ]
    end

    it 'decodes the TokenTypes' do
      expect(policies.map { |policy| policy.token_type.snapshot }).to eq [1, 1, 2, 2, 0]
    end

    # Every policy here leaves both of these null, which covers a null String
    # nested inside an array element inside another array element.
    it 'decodes the null fields within its elements' do
      expect(policies.map { |policy| policy.issued_token_type.snapshot }).to all(be_nil)
      expect(policies.map { |policy| policy.issuer_endpoint_url.snapshot }).to all(be_nil)
    end

    # The per token SecurityPolicyUri is not the endpoint's own. This endpoint
    # is None/None, yet four of its five policies demand a real policy for the
    # credential itself; only the anonymous one, which has no credential to
    # protect, leaves the field null.
    it 'decodes the per token SecurityPolicyUri' do
      expect(policies.map { |policy| policy.security_policy_uri.snapshot })
        .to eq [
          'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
          'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep',
          'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
          'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep',
          nil
        ]
    end
  end

  describe Rex::Proto::OpcUa::Services::GetEndpointsRequest do
    # No capture contains a request. The expected bytes are hand-built from the
    # GetEndpointsRequest StructuredType in reference/opcua/Opc.Ua.Types.bsd,
    # and are what the shipped module builds in build_get_endpoints.
    subject(:request) do
      described_class.new(
        request_header: { timestamp: 0, request_handle: 2, timeout_hint: 10_000 },
        endpoint_url: 'opc.tcp://192.0.2.1:4840'
      )
    end

    let(:url) { 'opc.tcp://192.0.2.1:4840' }

    it 'encodes the EndpointUrl after the RequestHeader' do
      header_length = Rex::Proto::OpcUa::Services::RequestHeader
                      .new(timestamp: 0, request_handle: 2, timeout_hint: 10_000).num_bytes

      expect(request.to_binary_s.byteslice(header_length, 4 + url.bytesize))
        .to eq [url.bytesize].pack('l<') + url
    end

    # Both filters are sent null, which asks for every endpoint. Null and empty
    # encode differently, and this comes from the declaration rather than from
    # the caller: BinData drops nil values when a record is built from a hash,
    # so a record that only accepted null by assignment would quietly send an
    # empty array to any caller that named neither field.
    it 'encodes both filters as null arrays without being told to' do
      expect(request.to_binary_s.byteslice(-8, 8)).to eq [-1, -1].pack('l<2')
    end

    it 'still reads an empty filter back as empty rather than null' do
      empty = request.to_binary_s.dup
      empty[-8, 8] = [0, 0].pack('l<2')

      expect(described_class.read(empty).locale_ids).not_to be_null
    end

    it 'round trips' do
      expect(described_class.read(request.to_binary_s).snapshot).to eq request.snapshot
    end
  end
end
