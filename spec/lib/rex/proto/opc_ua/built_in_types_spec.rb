# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/opc_ua/types'

# The structured built-in types of OPC-UA Specification Part 6, section 5.2.2.
# The length prefixed built-ins are covered in types_spec.rb and the array in
# opc_ua_array_spec.rb.
RSpec.describe 'Rex::Proto::OpcUa structured built-in types' do
  # See spec/file_fixtures/opc_ua/README.md for provenance. Offsets into the
  # capture were established by walking the response field by field; the walk
  # consumes the message exactly, 135 of 135 bytes.
  let(:response) do
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'open_secure_channel_response_node_opcua.bin'))
  end

  # The TypeId of the response, which follows the SequenceHeader.
  let(:type_id_offset) { 0x4F }
  # The AdditionalHeader of the ResponseHeader, an empty ExtensionObject whose
  # own TypeId is the null NodeId.
  let(:additional_header_offset) { 0x68 }
  # The ServiceDiagnostics of the ResponseHeader.
  let(:service_diagnostics_offset) { 0x63 }

  # The GetEndpoints response is the only capture carrying a LocalizedText. Its
  # first endpoint's ApplicationName begins 151 bytes in; the offset was
  # established by walking the response field by field, a walk that consumes the
  # message exactly and which services_spec.rb asserts.
  let(:get_endpoints_response) do
    File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'get_endpoints_response_node_opcua.bin'))
  end
  let(:application_name_offset) { 151 }

  describe Rex::Proto::OpcUa::Types::OpcUaNodeId do
    describe 'the FourByte form, against the captured response TypeId' do
      subject(:node_id) { described_class.read(response[type_id_offset..]) }

      it 'decodes the encoding byte' do
        expect(node_id.encoding_byte.snapshot).to eq described_class::FOUR_BYTE
      end

      it 'decodes the NamespaceIndex' do
        expect(node_id.namespace_index).to eq 0
      end

      # 449 is the DefaultBinary encoding of OpenSecureChannelResponse, which is
      # what makes this NodeId the thing that says what the message is.
      it 'decodes the identifier' do
        expect(node_id.identifier).to eq Rex::Proto::OpcUa::Enums::NodeIds::OPEN_SECURE_CHANNEL_RESPONSE
      end

      it 'occupies four bytes' do
        expect(node_id.num_bytes).to eq 4
      end

      it 're-encodes to the captured bytes' do
        expect(node_id.to_binary_s).to eq response.byteslice(type_id_offset, 4)
      end

      it 'is what .four_byte builds' do
        expect(described_class.four_byte(449).to_binary_s).to eq response.byteslice(type_id_offset, 4)
      end

      # The encoded form, which is how a service TypeId is written into a
      # message body. It exists so that the layer building those bodies does not
      # have to know that a TypeId is a FourByte NodeId in namespace 0.
      it 'is what .four_byte_binary encodes' do
        expect(described_class.four_byte_binary(449)).to eq response.byteslice(type_id_offset, 4)
      end

      it 'encodes the same bytes .four_byte would' do
        expect(described_class.four_byte_binary(428)).to eq described_class.four_byte(428).to_binary_s
      end

      it 'carries a namespace other than the standard one through' do
        expect(described_class.four_byte_binary(1, namespace_index: 2))
          .to eq described_class.four_byte(1, namespace_index: 2).to_binary_s
      end

      # The result is appended to as a service request is built up, so it has to
      # come back mutable rather than as a frozen literal.
      it 'returns a string that can be appended to' do
        expect { described_class.four_byte_binary(449) << 'x' }.not_to raise_error
      end
    end

    describe 'the TwoByte form, against the captured AdditionalHeader TypeId' do
      subject(:node_id) { described_class.read(response[additional_header_offset..]) }

      it 'occupies two bytes' do
        expect(node_id.num_bytes).to eq 2
      end

      it 'decodes the identifier' do
        expect(node_id.identifier).to eq 0
      end

      # TwoByte carries no NamespaceIndex on the wire at all. Reporting 0 rather
      # than nil is what lets a caller compare namespaces without first asking
      # which form it is looking at.
      it 'reports the namespace the form leaves implicit' do
        expect(node_id.namespace_index).to eq 0
      end

      # Null NodeId is how a sessionless AuthenticationToken and an empty
      # ExtensionObject TypeId are both sent, so it needs to be what a fresh
      # instance already is.
      it 'is what a default instance encodes to' do
        expect(described_class.new.to_binary_s).to eq "\x00\x00".b
      end
    end

    # No capture contains any of the remaining forms or either flag; every
    # NodeId in spec/file_fixtures/opc_ua uses encoding byte 0x01. The bytes
    # below are hand-built from the identifier table in OPC-UA Specification
    # Part 6, carried over unchanged from the reader in the module this library
    # replaces. This is recorded under Coverage limits in
    # spec/file_fixtures/opc_ua/README.md.
    describe 'the forms with no capture coverage' do
      it 'decodes the Numeric form' do
        node_id = described_class.read("\x02\x05\x00\x39\x30\x00\x00".b)

        expect(node_id.namespace_index).to eq 5
        expect(node_id.identifier).to eq 12_345
        expect(node_id.num_bytes).to eq 7
      end

      it 'decodes the String form' do
        node_id = described_class.read("\x03\x02\x00".b + [6].pack('l<') + 'MyNode')

        expect(node_id.namespace_index).to eq 2
        expect(node_id.identifier).to eq 'MyNode'
        expect(node_id.num_bytes).to eq 13
      end

      it 'decodes the GUID form' do
        guid = (0..15).to_a.pack('C*')
        node_id = described_class.read("\x04\x01\x00".b + guid)

        expect(node_id.namespace_index).to eq 1
        expect(node_id.identifier).to eq guid
        expect(node_id.num_bytes).to eq 19
      end

      it 'decodes the ByteString form' do
        node_id = described_class.read("\x05\x00\x00".b + [2].pack('l<') + "\xDE\xAD".b)

        expect(node_id.identifier).to eq "\xDE\xAD".b
        expect(node_id.num_bytes).to eq 9
      end

      it 'reads the trailing NamespaceUri when the 0x80 flag is set' do
        node_id = described_class.read("\x81\x00\xC1\x01".b + [3].pack('l<') + 'uri')

        expect(node_id.identifier).to eq 449
        expect(node_id.namespace_uri.snapshot).to eq 'uri'
        expect(node_id.num_bytes).to eq 11
      end

      it 'reads the trailing ServerIndex when the 0x40 flag is set' do
        node_id = described_class.read("\x41\x00\xC1\x01".b + [7].pack('V'))

        expect(node_id.server_index.snapshot).to eq 7
        expect(node_id.num_bytes).to eq 8
      end

      # The NamespaceUri precedes the ServerIndex, so a reader that had them the
      # wrong way round would still consume the right number of bytes and hand
      # back two wrong values.
      it 'reads both trailing fields in order when both flags are set' do
        node_id = described_class.read("\xC1\x00\xC1\x01".b + [3].pack('l<') + 'uri' + [7].pack('V'))

        expect(node_id.namespace_uri.snapshot).to eq 'uri'
        expect(node_id.server_index.snapshot).to eq 7
        expect(node_id.num_bytes).to eq 15
      end

      it 'omits the trailing fields when neither flag is set' do
        node_id = described_class.read("\x01\x00\xC1\x01".b)

        expect(node_id.snapshot).not_to have_key(:namespace_uri)
        expect(node_id.snapshot).not_to have_key(:server_index)
      end
    end

    # The length of an identifier form this does not know is itself unknown, so
    # there is nothing to skip past and no way to keep reading.
    it 'rejects an identifier form it does not know' do
      expect { described_class.read("\x06\x00\x00".b).num_bytes }
        .to raise_error(BinData::ValidityError, /encoding_byte/)
    end

    # The form field is six bits wide, not four. Masking with 0x0F would drop
    # bits 4 and 5 rather than object to them, so an encoding byte of 0x11 would
    # read as the FourByte form and go on to decode three bytes that mean
    # nothing. Both masks agree on every byte a conforming server can send, so
    # this reserved case is the only thing that distinguishes them.
    it 'masks the identifier form with six bits rather than four' do
      expect(described_class::FORM_MASK).to eq 0x3F
    end

    it 'rejects an encoding byte with a reserved bit set above the form' do
      expect { described_class.read("\x11\x00\xC1\x01".b).num_bytes }
        .to raise_error(BinData::ValidityError, /encoding_byte/)
    end

    it 'rejects a reserved bit even alongside a form it does know' do
      expect { described_class.read("\x21\x00\xC1\x01".b).num_bytes }
        .to raise_error(BinData::ValidityError, /encoding_byte/)
    end
  end

  describe Rex::Proto::OpcUa::Types::OpcUaExtensionObject do
    describe 'against the captured empty AdditionalHeader' do
      subject(:extension_object) { described_class.read(response[additional_header_offset..]) }

      # A null TypeId, an encoding of 0x00 and nothing after it.
      it 'occupies three bytes' do
        expect(extension_object.num_bytes).to eq 3
      end

      it 'decodes the encoding as carrying no body' do
        expect(extension_object.encoding.snapshot).to eq described_class::NO_BODY
      end

      it 're-encodes to the captured bytes' do
        expect(extension_object.to_binary_s).to eq response.byteslice(additional_header_offset, 3)
      end

      it 'is what a default instance encodes to' do
        expect(described_class.new.to_binary_s).to eq "\x00\x00\x00".b
      end
    end

    # Neither body form appears in any capture; both are hand-built from OPC-UA
    # Specification Part 6.
    describe 'the body forms with no capture coverage' do
      it 'decodes a ByteString body' do
        raw = "\x01\x00\xC1\x01\x01".b + [2].pack('l<') + "\xDE\xAD".b

        expect(described_class.read(raw).body.snapshot).to eq "\xDE\xAD".b
        expect(described_class.read(raw).num_bytes).to eq raw.bytesize
      end

      # An XmlElement has the ByteString wire format, so the difference between
      # the two encodings is what the bytes mean, not how they are framed.
      it 'decodes an XmlElement body' do
        raw = "\x01\x00\xC1\x01\x02".b + [4].pack('l<') + '<a/>'

        expect(described_class.read(raw).body.snapshot).to eq '<a/>'
        expect(described_class.read(raw).num_bytes).to eq raw.bytesize
      end
    end

    it 'rejects a body encoding it does not know' do
      expect { described_class.read("\x00\x00\x03".b).num_bytes }
        .to raise_error(BinData::ValidityError, /encoding/)
    end
  end

  describe Rex::Proto::OpcUa::Types::OpcUaLocalizedText do
    describe 'against the captured ApplicationName' do
      subject(:localized_text) { described_class.read(get_endpoints_response[application_name_offset..]) }

      it 'decodes the Text' do
        expect(localized_text.to_s).to eq 'NodeOPCUA'
      end

      it 'decodes the Locale' do
        expect(localized_text.locale.snapshot).to eq 'en-US'
      end

      it 'decodes the mask as carrying both fields' do
        expect(localized_text.encoding_mask.snapshot).to eq 0x03
      end

      # Locale is encoded ahead of Text. A reader with them the wrong way round
      # consumes the same number of bytes and returns both values swapped, which
      # is why the two are asserted separately rather than only by length.
      it 'accounts for the mask and both strings' do
        expect(localized_text.num_bytes).to eq 23
      end

      it 're-encodes to the captured bytes' do
        expect(localized_text.to_binary_s).to eq get_endpoints_response.byteslice(application_name_offset, 23)
      end
    end

    # Every LocalizedText in the captures has mask 0x03. The sparser masks are
    # hand-built from the LocalizedText StructuredType in
    # reference/opcua/Opc.Ua.Types.bsd, and are recorded under Coverage limits
    # in spec/file_fixtures/opc_ua/README.md.
    describe 'the masks with no capture coverage' do
      it 'decodes an empty LocalizedText as the mask alone' do
        localized_text = described_class.read("\x00".b)

        expect(localized_text.num_bytes).to eq 1
        expect(localized_text.to_s).to eq ''
        expect(localized_text).not_to be_text
      end

      it 'decodes a Locale with no Text' do
        localized_text = described_class.read("\x01".b + [2].pack('l<') + 'en')

        expect(localized_text.locale.snapshot).to eq 'en'
        expect(localized_text).not_to be_text
        expect(localized_text.num_bytes).to eq 7
      end

      # The common sparse case: a server that gives the text without saying what
      # language it is in. The Text has to be read from the byte after the mask,
      # not from where it would sit if a Locale had been present.
      it 'decodes a Text with no Locale' do
        localized_text = described_class.read("\x02".b + [3].pack('l<') + 'abc')

        expect(localized_text.to_s).to eq 'abc'
        expect(localized_text).not_to be_locale
        expect(localized_text.num_bytes).to eq 8
      end

      it 'round trips each mask' do
        %W[\x00 \x01#{[2].pack('l<')}en \x02#{[3].pack('l<')}abc].each do |raw|
          expect(described_class.read(raw.b).to_binary_s).to eq raw.b
        end
      end
    end
  end

  describe Rex::Proto::OpcUa::Types::OpcUaDiagnosticInfo do
    describe 'against the captured ServiceDiagnostics' do
      subject(:diagnostics) { described_class.read(response[service_diagnostics_offset..]) }

      it 'occupies the single mask byte' do
        expect(diagnostics.num_bytes).to eq 1
      end

      it 'decodes as empty' do
        expect(diagnostics.snapshot).to eq described_class::EMPTY
      end

      it 're-encodes to the captured byte' do
        expect(diagnostics.to_binary_s).to eq "\x00".b
      end
    end

    # Every request this library sends asks for no diagnostics, so a populated
    # DiagnosticInfo is a server answering a question it was not asked. The
    # seven optional fields it would carry are deliberately not modelled, and
    # skipping past a structure of unknown length is not possible, so this has
    # to fail rather than continue.
    it 'refuses to read a populated DiagnosticInfo' do
      expect { described_class.read("\x01".b) }
        .to raise_error(BinData::ValidityError, /mask 0x01, but no diagnostics were requested/)
    end

    it 'names the mask it refused' do
      expect { described_class.read("\x7F".b) }
        .to raise_error(BinData::ValidityError, /mask 0x7F/)
    end

    it 'refuses to write anything but empty' do
      expect { described_class.new(1).to_binary_s }
        .to raise_error(BinData::ValidityError, /can only be written empty/)
    end
  end
end
