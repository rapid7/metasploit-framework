# -*- coding: binary -*-

require 'spec_helper'
require 'rex/text'

RSpec.describe 'Rex::Proto::OpcUa length prefixed types' do
  # A null value is a length prefix of -1 with no bytes following it.
  let(:null_binary) { [-1].pack('l<') }
  # An empty value is a length prefix of 0, which the specification treats as
  # distinct from null.
  let(:empty_binary) { [0].pack('l<') }

  # Both types share the Part 6 section 5.2.2 length prefix semantics and
  # differ only in how they present the bytes that follow it.
  shared_examples 'a length prefixed OPC-UA type' do
    describe '.read' do
      it 'decodes a null value as nil' do
        expect(described_class.read(null_binary).snapshot).to be_nil
      end

      it 'decodes an empty value as an empty string' do
        expect(described_class.read(empty_binary).snapshot).to eq ''
      end

      it 'decodes a populated value' do
        expect(described_class.read([value.bytesize].pack('l<') + value).snapshot).to eq value
      end

      it 'distinguishes null from empty' do
        expect(described_class.read(null_binary).snapshot).to be_nil
        expect(described_class.read(empty_binary).snapshot).not_to be_nil
      end

      it 'consumes only the prefix when the value is null' do
        expect(described_class.read(null_binary).num_bytes).to eq 4
      end

      it 'treats a negative length other than -1 as null' do
        expect(described_class.read([-5].pack('l<')).snapshot).to be_nil
      end

      it 'raises when the buffer is shorter than the declared length' do
        expect { described_class.read([16].pack('l<') + 'short') }.to raise_error(IOError)
      end

      it 'raises when the buffer is shorter than the prefix' do
        expect { described_class.read("\x00\x00") }.to raise_error(IOError)
      end
    end

    describe '#to_binary_s' do
      it 'encodes nil as a null length prefix' do
        expect(described_class.new(nil).to_binary_s).to eq null_binary
      end

      it 'encodes a default constructed value as null' do
        expect(described_class.new.to_binary_s).to eq null_binary
      end

      it 'encodes an empty string as a zero length prefix' do
        expect(described_class.new('').to_binary_s).to eq empty_binary
      end

      it 'encodes a populated value' do
        expect(described_class.new(value).to_binary_s).to eq [value.bytesize].pack('l<') + value
      end
    end

    describe '#assign' do
      # BasePrimitive#assign rejects nil, so the override is what makes a field
      # assignment of null work rather than raise.
      it 'accepts nil and encodes it as null' do
        subject = described_class.new(value)
        subject.assign(nil)
        expect(subject.snapshot).to be_nil
        expect(subject.to_binary_s).to eq null_binary
      end
    end

    describe 'round trip' do
      it 'preserves null through decode and re-encode' do
        expect(described_class.read(null_binary).to_binary_s).to eq null_binary
      end

      it 'preserves empty through decode and re-encode' do
        expect(described_class.read(empty_binary).to_binary_s).to eq empty_binary
      end

      it 'preserves a populated value through decode and re-encode' do
        binary = [value.bytesize].pack('l<') + value
        expect(described_class.read(binary).to_binary_s).to eq binary
      end

      it 'preserves null through encode and re-decode' do
        expect(described_class.read(described_class.new(nil).to_binary_s).snapshot).to be_nil
      end

      it 'preserves empty through encode and re-decode' do
        expect(described_class.read(described_class.new('').to_binary_s).snapshot).to eq ''
      end

      it 'preserves a populated value through encode and re-decode' do
        expect(described_class.read(described_class.new(value).to_binary_s).snapshot).to eq value
      end
    end
  end

  describe Rex::Proto::OpcUa::Types::OpcUaByteString do
    let(:value) { Rex::Text.rand_text_alphanumeric(10).b }

    it_behaves_like 'a length prefixed OPC-UA type'

    it 'decodes bytes that are not valid UTF-8 without altering them' do
      raw = "\x00\xFF\xFE\x80".b
      expect(described_class.read([raw.bytesize].pack('l<') + raw).snapshot).to eq raw
    end

    it 'decodes to a binary string' do
      expect(described_class.read([value.bytesize].pack('l<') + value).snapshot.encoding).to eq ::Encoding::ASCII_8BIT
    end

    it 'encodes the byte length of a multi-byte value, not its character length' do
      raw = "caf\xC3\xA9".b
      expect(described_class.new(raw).to_binary_s).to eq [5].pack('l<') + raw
    end
  end

  describe Rex::Proto::OpcUa::Types::OpcUaString do
    let(:value) { Rex::Text.rand_text_alphanumeric(10) }

    # This source file is binary encoded, so a bare literal containing an
    # e-acute would be ASCII-8BIT and would never compare equal to the UTF-8
    # string the type produces. The \u escape forces the literal to UTF-8
    # regardless of the file encoding, which is what makes this a real test of
    # the decoded encoding rather than of the byte sequence alone.
    let(:multi_byte_text) { "caf\u00E9" }
    let(:multi_byte_bytes) { "caf\xC3\xA9".b }

    it_behaves_like 'a length prefixed OPC-UA type'

    it 'decodes to UTF-8' do
      expect(described_class.read([value.bytesize].pack('l<') + value).snapshot.encoding).to eq ::Encoding::UTF_8
    end

    # Transcoding from BINARY to UTF-8 would treat every byte at or above 0x80
    # as undefined and replace it, so a valid multi-byte value surviving intact
    # is what proves the type scrubs rather than transcodes.
    it 'preserves valid multi-byte UTF-8' do
      binary = [multi_byte_bytes.bytesize].pack('l<') + multi_byte_bytes
      expect(described_class.read(binary).snapshot).to eq multi_byte_text
    end

    it 'replaces invalid UTF-8 sequences' do
      raw = "ab\xFF\xFEcd".b
      expect(described_class.read([raw.bytesize].pack('l<') + raw).snapshot).to eq 'ab??cd'
    end

    it 'decodes invalid UTF-8 to a string that is itself valid UTF-8' do
      raw = "ab\xFF\xFEcd".b
      expect(described_class.read([raw.bytesize].pack('l<') + raw).snapshot).to be_valid_encoding
    end

    it 'encodes the byte length of a multi-byte value, not its character length' do
      expect(multi_byte_text.length).to eq 4
      expect(described_class.new(multi_byte_text).to_binary_s).to eq [5].pack('l<') + multi_byte_bytes
    end

    it 'round trips valid multi-byte UTF-8' do
      binary = [multi_byte_bytes.bytesize].pack('l<') + multi_byte_bytes
      expect(described_class.read(binary).to_binary_s).to eq binary
    end
  end

  # The synthetic cases above assert the intended behaviour; these assert it
  # against bytes a real server put on the wire.
  #
  # The AsymmetricAlgorithmSecurityHeader of an OpenSecureChannelResponse opens
  # with a populated SecurityPolicyUri String followed by two ByteStrings that
  # are null under SecurityPolicy None, and the response ends with a null
  # ServerNonce. That gives real examples of both the populated and the null
  # form, and of one following the other, which is what the record layer will
  # depend on. See spec/file_fixtures/opc_ua/README.md for provenance.
  describe 'a captured OpenSecureChannelResponse' do
    let(:response) do
      File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'open_secure_channel_response_node_opcua.bin'))
    end

    # The security header follows the 8 byte message header and the UInt32
    # SecureChannelId.
    let(:security_header) { response[12..] }

    let(:security_policy_uri) { Rex::Proto::OpcUa::Types::OpcUaString.read(security_header) }

    it 'decodes the populated SecurityPolicyUri' do
      expect(security_policy_uri.snapshot).to eq 'http://opcfoundation.org/UA/SecurityPolicy#None'
    end

    # Advancing by num_bytes is what proves the length prefix was accounted for
    # exactly, rather than the next field merely happening to decode.
    it 'decodes the SenderCertificate that follows it as null' do
      sender_certificate = Rex::Proto::OpcUa::Types::OpcUaByteString.read(security_header[security_policy_uri.num_bytes..])
      expect(sender_certificate.snapshot).to be_nil
    end

    it 'decodes the trailing ServerNonce as null' do
      expect(Rex::Proto::OpcUa::Types::OpcUaByteString.read(response[-4..]).snapshot).to be_nil
    end

    it 're-encodes the trailing ServerNonce to the captured bytes' do
      expect(Rex::Proto::OpcUa::Types::OpcUaByteString.read(response[-4..]).to_binary_s).to eq response[-4..]
    end
  end
end
