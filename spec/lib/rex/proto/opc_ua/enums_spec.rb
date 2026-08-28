# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::OpcUa::Enums do
  # These values are transcribed from the OPC Foundation's machine-readable
  # definitions. Pinning them here means a transcription slip fails a test
  # rather than silently mislabelling a scan result.
  describe 'STATUS_CODES' do
    {
      0x807D0000 => 'Bad_TcpServerTooBusy',
      0x807E0000 => 'Bad_TcpMessageTypeInvalid',
      0x807F0000 => 'Bad_TcpSecureChannelUnknown',
      0x80800000 => 'Bad_TcpMessageTooLarge',
      0x80810000 => 'Bad_TcpNotEnoughResources',
      0x80820000 => 'Bad_TcpInternalError',
      0x80830000 => 'Bad_TcpEndpointUrlInvalid',
      0x80BE0000 => 'Bad_ProtocolVersionUnsupported',
      0x80130000 => 'Bad_SecurityChecksFailed',
      0x80120000 => 'Bad_CertificateInvalid',
      0x80840000 => 'Bad_RequestInterrupted',
      0x80850000 => 'Bad_RequestTimeout',
      0x80860000 => 'Bad_SecureChannelClosed',
      0x80870000 => 'Bad_SecureChannelTokenUnknown',
      0x80AC0000 => 'Bad_ConnectionRejected',
      0x80AE0000 => 'Bad_ConnectionClosed'
    }.each do |code, name|
      it "maps #{format('0x%08X', code)} to #{name}" do
        expect(described_class::STATUS_CODES[code]).to eq name
      end
    end

    it 'carries no duplicate names' do
      names = described_class::STATUS_CODES.values
      expect(names.uniq.length).to eq names.length
    end

    # Every StatusCode here has the severity bits set to Bad and no
    # subcode or info bits, per Part 4 section 7.34.
    it 'holds only Bad severity codes with an empty low half' do
      described_class::STATUS_CODES.each_key do |code|
        expect(code & 0xC0000000).to eq 0x80000000
        expect(code & 0x0000FFFF).to eq 0
      end
    end
  end

  describe '.status_code_name' do
    it 'names a known code' do
      expect(described_class.status_code_name(0x807D0000)).to eq 'Bad_TcpServerTooBusy'
    end

    it 'falls back to hexadecimal for an unknown code' do
      expect(described_class.status_code_name(0x80AB0000)).to eq '0x80AB0000'
    end

    it 'pads the fallback to eight digits' do
      expect(described_class.status_code_name(0)).to eq '0x00000000'
    end
  end

  describe 'NodeIds' do
    # A request and its response differ by three, the intervening identifier
    # being the XML encoding. Both response values were also read off the wire
    # from the captures in spec/file_fixtures/opc_ua.
    {
      'OPEN_SECURE_CHANNEL' => [446, 449],
      'CLOSE_SECURE_CHANNEL' => [452, 455],
      'GET_ENDPOINTS' => [428, 431]
    }.each do |service, (request, response)|
      it "identifies #{service} as #{request} and #{response}" do
        expect(described_class::NodeIds.const_get("#{service}_REQUEST")).to eq request
        expect(described_class::NodeIds.const_get("#{service}_RESPONSE")).to eq response
      end
    end

    it 'matches the OpenSecureChannelResponse TypeId in the capture' do
      opn = File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'open_secure_channel_response_node_opcua.bin'))
      # FourByte NodeId at offset 79: encoding, namespace, then a UInt16.
      expect(opn.byteslice(79, 1).unpack1('C')).to eq 0x01
      expect(opn.byteslice(81, 2).unpack1('v')).to eq described_class::NodeIds::OPEN_SECURE_CHANNEL_RESPONSE
    end

    it 'matches the GetEndpointsResponse TypeId in the capture' do
      ge = File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'get_endpoints_response_node_opcua.bin'))
      expect(ge.byteslice(24, 1).unpack1('C')).to eq 0x01
      expect(ge.byteslice(26, 2).unpack1('v')).to eq described_class::NodeIds::GET_ENDPOINTS_RESPONSE
    end
  end

  describe '.security_mode_name' do
    it { expect(described_class.security_mode_name(0)).to eq 'Invalid' }
    it { expect(described_class.security_mode_name(1)).to eq 'None' }
    it { expect(described_class.security_mode_name(2)).to eq 'Sign' }
    it { expect(described_class.security_mode_name(3)).to eq 'SignAndEncrypt' }

    it 'reports an out of range mode with its value' do
      expect(described_class.security_mode_name(9)).to eq 'Unknown(9)'
    end
  end

  describe '.user_token_type_name' do
    it { expect(described_class.user_token_type_name(0)).to eq 'Anonymous' }
    it { expect(described_class.user_token_type_name(1)).to eq 'UserName' }
    it { expect(described_class.user_token_type_name(2)).to eq 'Certificate' }
    it { expect(described_class.user_token_type_name(3)).to eq 'IssuedToken' }

    it 'reports an out of range type with its value' do
      expect(described_class.user_token_type_name(9)).to eq 'Unknown(9)'
    end
  end

  describe '.security_policy_name' do
    it 'reduces a policy URI to its fragment' do
      expect(described_class.security_policy_name(described_class::NONE_POLICY_URI)).to eq 'None'
    end

    it 'reduces the other policies advertised in the capture' do
      expect(
        described_class.security_policy_name('http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256')
      ).to eq 'Basic256Sha256'
    end

    it 'returns a URI with no fragment whole' do
      expect(described_class.security_policy_name('urn:vendor:policy')).to eq 'urn:vendor:policy'
    end

    it 'reports nil as unknown' do
      expect(described_class.security_policy_name(nil)).to eq 'Unknown'
    end

    it 'reports an empty URI as unknown' do
      expect(described_class.security_policy_name('')).to eq 'Unknown'
    end
  end

  describe 'NONE_POLICY_URI' do
    it 'is the URI the captured server advertises for its unsecured endpoint' do
      ge = File.binread(File.join(FILE_FIXTURES_PATH, 'opc_ua', 'get_endpoints_response_node_opcua.bin'))
      expect(ge).to include(described_class::NONE_POLICY_URI)
    end
  end
end
