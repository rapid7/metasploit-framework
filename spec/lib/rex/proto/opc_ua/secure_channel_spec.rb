# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/opc_ua/secure_channel'

RSpec.describe 'Rex::Proto::OpcUa::SecureChannel' do
  # The captured OpenSecureChannelResponse, whole and including its 8 byte
  # message header. See spec/file_fixtures/opc_ua/README.md for provenance.
  let(:response) do
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'open_secure_channel_response_node_opcua.bin'))
  end

  # Everything after the message header, which is what a caller has once
  # Rex::Proto::OpcUa::Tcp::MessageStream has framed the message.
  let(:message_body) { response[Rex::Proto::OpcUa::Tcp::HEADER_LEN..] }

  # Offsets into the capture, all measured from the start of the file. They were
  # established by walking the response field by field; the walk consumes the
  # message exactly, which the end to end example below is the assertion of.
  let(:security_header_offset) { 0x0C }
  let(:sequence_header_offset) { 0x47 }
  let(:type_id_offset) { 0x4F }
  let(:response_body_offset) { 0x53 }
  let(:security_token_offset) { 0x6F }

  describe Rex::Proto::OpcUa::SecureChannel::AsymmetricSecurityHeader do
    subject(:security_header) { described_class.read(response[security_header_offset..]) }

    it 'decodes the SecurityPolicyUri' do
      expect(security_header.security_policy_uri.snapshot).to eq Rex::Proto::OpcUa::Enums::NONE_POLICY_URI
    end

    # Under the None policy there is no certificate to send, and null is not the
    # same as an empty ByteString; a re-encode has to preserve which one it was.
    it 'decodes the SenderCertificate as null' do
      expect(security_header.sender_certificate.snapshot).to be_nil
    end

    it 'decodes the ReceiverCertificateThumbprint as null' do
      expect(security_header.receiver_certificate_thumbprint.snapshot).to be_nil
    end

    it 'accounts for the whole header' do
      expect(security_header.num_bytes).to eq sequence_header_offset - security_header_offset
    end

    it 're-encodes to the captured bytes' do
      expect(security_header.to_binary_s).to eq response[security_header_offset...sequence_header_offset]
    end
  end

  describe Rex::Proto::OpcUa::SecureChannel::SequenceHeader do
    subject(:sequence_header) { described_class.read(response[sequence_header_offset..]) }

    it 'decodes the SequenceNumber' do
      expect(sequence_header.sequence_number.snapshot).to eq 1
    end

    it 'decodes the RequestId' do
      expect(sequence_header.request_id.snapshot).to eq 1
    end

    it 'occupies eight bytes' do
      expect(sequence_header.num_bytes).to eq 8
    end
  end

  describe Rex::Proto::OpcUa::SecureChannel::SymmetricSecurityHeader do
    it 'is a single TokenId' do
      expect(described_class.new(token_id: 1).to_binary_s).to eq [1].pack('V')
    end

    # A MSG chunk repeats the SecureChannelId, this header and a SequenceHeader
    # ahead of its slice of the payload. That is the prefix
    # Rex::Proto::OpcUa::Tcp strips by length, so the two files have to agree on
    # what it adds up to.
    it 'accounts for the stripped MSG prefix together with the SequenceHeader' do
      prefix = 4 + described_class.new.num_bytes +
               Rex::Proto::OpcUa::SecureChannel::SequenceHeader.new.num_bytes

      expect(prefix).to eq Rex::Proto::OpcUa::Tcp::SECURE_MSG_PREFIX_LEN
    end
  end

  describe Rex::Proto::OpcUa::SecureChannel::ChannelSecurityToken do
    subject(:token) { described_class.read(response[security_token_offset..]) }

    it 'decodes the ChannelId' do
      expect(token.channel_id.snapshot).to eq 6
    end

    # The ChannelId inside the token is the same channel as the plaintext
    # SecureChannelId the message opens with. A record that had the token
    # starting a field early or late would break that agreement.
    it 'decodes the ChannelId the message header already named' do
      expect(token.channel_id.snapshot).to eq message_body.byteslice(0, 4).unpack1('V')
    end

    it 'decodes the TokenId' do
      expect(token.token_id.snapshot).to eq 1
    end

    it 'decodes the CreatedAt' do
      expect(token.created_at.to_time).to eq ::Time.utc(2026, 8, 27, 0, 34, 59) + Rational(703, 1000)
    end

    # Ten minutes, where the client asked for an hour. Reading it is the point
    # of modelling the whole token: it is the server's answer, not the client's
    # request granted.
    it 'decodes the RevisedLifetime' do
      expect(token.revised_lifetime.snapshot).to eq 600_000
    end

    it 'occupies twenty bytes' do
      expect(token.num_bytes).to eq 20
    end

    it 're-encodes to the captured bytes' do
      expect(token.to_binary_s).to eq response.byteslice(security_token_offset, 20)
    end
  end

  describe Rex::Proto::OpcUa::SecureChannel::OpenSecureChannelResponse do
    subject(:open_response) { described_class.read(response[response_body_offset..]) }

    it 'decodes the ServerProtocolVersion' do
      expect(open_response.server_protocol_version.snapshot).to eq 0
    end

    it 'decodes the SecurityToken' do
      expect(open_response.security_token.token_id.snapshot).to eq 1
      expect(open_response.security_token.revised_lifetime.snapshot).to eq 600_000
    end

    # The ServerNonce is null under the None policy, there being no key material
    # to derive. It is the last field of the response, so reading it is what
    # makes the record account for the message rather than stop at the last
    # field a caller happens to want.
    it 'decodes the ServerNonce as null' do
      expect(open_response.server_nonce.snapshot).to be_nil
    end

    it 'accounts for the rest of the message' do
      expect(open_response.num_bytes).to eq response.bytesize - response_body_offset
    end
  end

  # The records above each cover one structure. This covers the claim that they
  # tile the message: the whole 135 byte capture is consumed by the sequence of
  # them, with nothing skipped, nothing counted twice and nothing left over.
  #
  # The message body is not itself a record. The envelope of a SecureChannel
  # message is the same for a request and a response, so what follows the
  # SequenceHeader is decided by the TypeId that comes next, which is why the
  # caller reads it and dispatches rather than a record doing it.
  describe 'the captured message end to end' do
    subject(:decoded) do
      offset = 0
      parts = {}

      parts[:secure_channel_id] = message_body.byteslice(offset, 4).unpack1('V')
      offset += 4

      %i[security_header sequence_header type_id response].zip(
        [
          Rex::Proto::OpcUa::SecureChannel::AsymmetricSecurityHeader,
          Rex::Proto::OpcUa::SecureChannel::SequenceHeader,
          Rex::Proto::OpcUa::Types::OpcUaNodeId,
          Rex::Proto::OpcUa::SecureChannel::OpenSecureChannelResponse
        ]
      ).each do |name, klass|
        parts[name] = klass.read(message_body[offset..])
        offset += parts[name].num_bytes
      end

      parts.merge(consumed: offset)
    end

    it 'consumes the whole message with nothing left over' do
      expect(decoded[:consumed]).to eq message_body.bytesize
    end

    it 'consumes all 135 bytes of the capture once the message header is counted' do
      expect(decoded[:consumed] + Rex::Proto::OpcUa::Tcp::HEADER_LEN).to eq 135
    end

    it 'identifies the message from its TypeId' do
      expect(decoded[:type_id].identifier).to eq Rex::Proto::OpcUa::Enums::NodeIds::OPEN_SECURE_CHANNEL_RESPONSE
    end

    it 're-encodes byte for byte to the captured message body' do
      rebuilt = [decoded[:secure_channel_id]].pack('V') +
                decoded[:security_header].to_binary_s +
                decoded[:sequence_header].to_binary_s +
                decoded[:type_id].to_binary_s +
                decoded[:response].to_binary_s

      expect(rebuilt).to eq message_body
    end
  end

  describe Rex::Proto::OpcUa::SecureChannel::OpenSecureChannelRequest do
    # A timestamp taken from the capture rather than the clock, so that the
    # expected bytes below are fixed.
    let(:timestamp) { 134_322_644_997_030_000 }

    subject(:request) do
      described_class.new(
        request_header: {
          timestamp: timestamp,
          request_handle: 1,
          return_diagnostics: 0,
          timeout_hint: 10_000
        },
        client_protocol_version: 0,
        request_type: described_class::ISSUE,
        security_mode: 1,
        requested_lifetime: 3_600_000
      )
    end

    # Byte for byte what the shipped module builds for the same call. Pinning it
    # here is what says the record layer produces the same wire form as the code
    # it replaces, rather than merely something that decodes.
    let(:expected) do
      [0x00, 0x00].pack('CC') +           # AuthenticationToken: null NodeId
        [timestamp].pack('q<') +          # Timestamp
        [1].pack('V') +                   # RequestHandle
        [0].pack('V') +                   # ReturnDiagnostics: none
        [-1].pack('l<') +                 # AuditEntryId: null
        [10_000].pack('V') +              # TimeoutHint in milliseconds
        [0x00, 0x00, 0x00].pack('CCC') +  # AdditionalHeader: null ExtensionObject
        [0].pack('V') +                   # ClientProtocolVersion
        [0].pack('V') +                   # RequestType: Issue
        [1].pack('V') +                   # MessageSecurityMode: None
        [-1].pack('l<') +                 # ClientNonce: null under the None policy
        [3_600_000].pack('V')             # RequestedLifetime in milliseconds
    end

    it 'encodes to the bytes an OpenSecureChannel for SecurityPolicy None needs' do
      expect(request.to_binary_s).to eq expected
    end

    # The defaults carry the two fields that have to be null rather than empty,
    # so a caller that names neither still sends a legal request.
    it 'defaults the AuditEntryId to null' do
      expect(request.request_header.audit_entry_id.snapshot).to be_nil
    end

    it 'defaults the ClientNonce to null' do
      expect(request.client_nonce.snapshot).to be_nil
    end

    it 'defaults the AuthenticationToken to the null NodeId of a sessionless request' do
      expect(request.request_header.authentication_token.to_binary_s).to eq "\x00\x00".b
    end

    it 'round trips' do
      expect(described_class.read(request.to_binary_s).snapshot).to eq request.snapshot
    end
  end

  describe Rex::Proto::OpcUa::SecureChannel::CloseSecureChannelRequest do
    # The channel being closed is the one the message is sent on, so the request
    # is its header and nothing else.
    subject(:request) do
      described_class.new(request_header: { timestamp: 0, request_handle: 3, timeout_hint: 10_000 })
    end

    it 'encodes to a RequestHeader alone' do
      expect(request.to_binary_s)
        .to eq Rex::Proto::OpcUa::Services::RequestHeader
        .new(timestamp: 0, request_handle: 3, timeout_hint: 10_000).to_binary_s
    end

    it 'round trips' do
      expect(described_class.read(request.to_binary_s).snapshot).to eq request.snapshot
    end
  end
end
