# -*- coding: binary -*-

require 'spec_helper'
# BinData resolves field types when a record's class body is evaluated, so both
# the library types and the UserTokenPolicy the examples below read have to be
# registered first. Under Zeitwerk they would otherwise not load until first
# referenced.
require 'rex/proto/opc_ua/services'

RSpec.describe Rex::Proto::OpcUa::Types::OpcUaArray do
  let(:null_binary) { [-1].pack('l<') }
  let(:empty_binary) { [0].pack('l<') }

  # Three uint16 elements, the simplest thing that shows elements were read
  # rather than merely counted.
  let(:values) { [10, 20, 30] }
  let(:populated_binary) { [values.length].pack('l<') + values.pack('v*') }

  subject(:array) { described_class.new(type: :uint16le) }

  describe '.read' do
    it 'decodes a populated array' do
      expect(described_class.read(populated_binary, type: :uint16le).snapshot).to eq values
    end

    # BinData::Array installs its read strategy with #extend, so a count prefix
    # implemented as a plain method override is shadowed and yields an empty
    # array with no error raised. This is the guard against that regression.
    it 'decodes a populated array to the declared element count, not to empty' do
      expect(described_class.read(populated_binary, type: :uint16le).length).to eq values.length
    end

    it 'decodes a null array as empty' do
      expect(described_class.read(null_binary, type: :uint16le).length).to eq 0
    end

    it 'reports a null array as null' do
      expect(described_class.read(null_binary, type: :uint16le)).to be_null
    end

    it 'decodes an empty array as empty' do
      expect(described_class.read(empty_binary, type: :uint16le).length).to eq 0
    end

    it 'does not report an empty array as null' do
      expect(described_class.read(empty_binary, type: :uint16le)).not_to be_null
    end

    it 'consumes only the count prefix when the array is null' do
      expect(described_class.read(null_binary, type: :uint16le).num_bytes).to eq 4
    end

    it 'treats a negative count other than -1 as null' do
      expect(described_class.read([-5].pack('l<'), type: :uint16le)).to be_null
    end

    it 'raises when the buffer holds fewer elements than the count claims' do
      expect { described_class.read([4].pack('l<') + [1, 2].pack('v*'), type: :uint16le) }.to raise_error(IOError)
    end
  end

  describe 'max_length' do
    it 'rejects a count above the ceiling' do
      expect { described_class.read(populated_binary, type: :uint16le, max_length: 2) }
        .to raise_error(BinData::ValidityError, /exceeds the 2 element ceiling/)
    end

    it 'accepts a count equal to the ceiling' do
      expect(described_class.read(populated_binary, type: :uint16le, max_length: 3).length).to eq 3
    end

    it 'rejects before allocating the claimed elements' do
      absurd = [2**31 - 1].pack('l<')
      expect { described_class.read(absurd, type: :uint16le) }.to raise_error(BinData::ValidityError)
    end

    it 'applies a default ceiling when the declaration site gives none' do
      over_default = [described_class::DEFAULT_MAX_LENGTH + 1].pack('l<')
      expect { described_class.read(over_default, type: :uint16le) }.to raise_error(BinData::ValidityError)
    end

    it 'reads beyond the default ceiling when the declaration site raises it' do
      long = [600].pack('l<') + ([1] * 600).pack('v*')
      expect(described_class.read(long, type: :uint16le, max_length: 600).length).to eq 600
    end

    # There is no way to switch the ceiling off, which is the point of it.
    it 'refuses a nil ceiling' do
      expect { described_class.read(populated_binary, type: :uint16le, max_length: nil) }
        .to raise_error(ArgumentError, /has nil value/)
    end
  end

  describe '#to_binary_s' do
    it 'encodes a populated array' do
      array.assign(values)
      expect(array.to_binary_s).to eq populated_binary
    end

    it 'encodes an empty array as a zero count' do
      array.assign([])
      expect(array.to_binary_s).to eq empty_binary
    end

    it 'encodes nil as a null count' do
      array.assign(nil)
      expect(array.to_binary_s).to eq null_binary
    end
  end

  describe 'round trip' do
    it 'preserves a populated array' do
      expect(described_class.read(populated_binary, type: :uint16le).to_binary_s).to eq populated_binary
    end

    it 'preserves empty' do
      expect(described_class.read(empty_binary, type: :uint16le).to_binary_s).to eq empty_binary
    end

    # Null and empty both present as an empty array, so this is what keeps the
    # two from collapsing into one another across a decode and re-encode.
    it 'preserves null rather than degrading it to empty' do
      expect(described_class.read(null_binary, type: :uint16le).to_binary_s).to eq null_binary
    end
  end

  # Offsets into the capture were established by walking the response field by
  # field; the walk consumes the message exactly, 10648 of 10648 bytes. See
  # spec/file_fixtures/opc_ua/README.md for provenance.
  describe 'against a captured GetEndpointsResponse' do
    let(:response) do
      File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'get_endpoints_response_node_opcua.bin'))
    end

    # The EndpointDescription array begins after the message header, the secure
    # conversation prefix, the TypeId and the ResponseHeader.
    let(:endpoint_array_offset) { 52 }
    # UserTokenPolicy arrays of the first two endpoints.
    let(:five_token_offset) { 1327 }
    let(:three_token_offset) { 3141 }

    # EndpointDescription does not exist yet, so the element type here is a
    # single byte and only the count is under test. The arrays read with real
    # elements below.
    it 'decodes the endpoint count' do
      expect(described_class.read(response[endpoint_array_offset..], type: :uint8).length).to eq 7
    end

    it 'rejects the endpoint count against a lower ceiling' do
      expect { described_class.read(response[endpoint_array_offset..], type: :uint8, max_length: 5) }
        .to raise_error(BinData::ValidityError, /array length 7 exceeds/)
    end

    context 'the first endpoint, which advertises five token policies' do
      subject(:policies) do
        described_class.read(response[five_token_offset..], type: :user_token_policy)
      end

      it 'decodes five elements' do
        expect(policies.length).to eq 5
      end

      it 'decodes each element rather than only counting them' do
        expect(policies.map { |p| p.policy_id.snapshot }).to eq %w[
          username_basic256Sha256
          username_aes128Sha256RsaOaep
          certificate_basic256Sha256
          certificate_aes128Sha256RsaOaep
          anonymous
        ]
      end

      it 'decodes the token types' do
        expect(policies.map { |p| p.token_type.snapshot }).to eq [1, 1, 2, 2, 0]
      end

      # Every policy here leaves IssuedTokenType and IssuerEndpointUrl null, so
      # this covers a null ByteString nested inside an array element.
      it 'decodes the null fields within its elements' do
        expect(policies.map { |p| p.issued_token_type.snapshot }).to all(be_nil)
        expect(policies.map { |p| p.issuer_endpoint_url.snapshot }).to all(be_nil)
      end

      it 'is not null' do
        expect(policies).not_to be_null
      end
    end

    context 'the second endpoint, which advertises three token policies' do
      subject(:policies) do
        described_class.read(response[three_token_offset..], type: :user_token_policy)
      end

      it 'decodes three elements' do
        expect(policies.length).to eq 3
      end

      it 'decodes each element' do
        expect(policies.map { |p| p.policy_id.snapshot }).to eq %w[usernamePassword certificateX509 anonymous_0]
      end
    end
  end
end
