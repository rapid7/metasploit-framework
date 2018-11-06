RSpec.describe RubySMB::Dcerpc::Request do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdu_header }
  it { is_expected.to respond_to :alloc_hint }
  it { is_expected.to respond_to :p_cont_id }
  it { is_expected.to respond_to :opnum }
  it { is_expected.to respond_to :object }
  it { is_expected.to respond_to :stub }
  it { is_expected.to respond_to :auth_verifier }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#pdu_header' do
    subject(:header) { packet.pdu_header }

    it 'is a standard PDU Header' do
      expect(header).to be_a RubySMB::Dcerpc::PDUHeader
    end

    it 'should have the #ptype field set to PTypes::BIND_ACK' do
      expect(header.ptype).to eq RubySMB::Dcerpc::PTypes::REQUEST
    end
  end

  describe '#alloc_hint' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.alloc_hint).to be_a BinData::Uint32le
    end

    it 'should be the size of the #stub field' do
      packet = described_class.new({ :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }, host: '1.2.3.4')
      expect(packet.alloc_hint).to eq(packet.stub.do_num_bytes)
    end
  end

  describe '#p_cont_id' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.p_cont_id).to be_a BinData::Uint16le
    end
  end

  describe '#opnum' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.opnum).to be_a BinData::Uint16le
    end
  end

  describe '#object' do
    it 'is a Uuid' do
      expect(packet.object).to be_a RubySMB::Dcerpc::Uuid
    end

    it 'only exists if #object_uuid header flag is set' do
      packet.pdu_header.pfc_flags.object_uuid = 1
      expect(packet.object?).to be true
    end

    it 'does not  exist if #object_uuid header flag is not set' do
      packet.pdu_header.pfc_flags.object_uuid = 0
      expect(packet.object?).to be false
    end
  end

  describe '#stub' do
    it 'is a Bindata Choice' do
      expect(packet.stub).to be_a BinData::Choice
    end

    context 'with a NetShareEnumAll stub' do

      it 'uses opnum as a selector' do
        packet = described_class.new({ :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }, host: '1.2.3.4')
        expect(packet.stub.selection).to eq(packet.opnum)
      end
    end
  end

  describe '#auth_verifier' do
    it 'should be a string' do
      expect(packet.auth_verifier).to be_a BinData::String
    end

    it 'should not exist if the #auth_length PDU header field is 0' do
      packet.pdu_header.auth_length = 0
      expect(packet.auth_verifier?).to be false
    end

    it 'should exist only if the #auth_length PDU header field is greater than 0' do
      packet.pdu_header.auth_length = 10
      expect(packet.auth_verifier?).to be true
    end

    it 'reads #auth_length bytes' do
      auth_verifier = '12345678'
      packet.pdu_header.auth_length = 6
      packet.auth_verifier.read(auth_verifier)
      expect(packet.auth_verifier).to eq(auth_verifier[0,6])
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new({ :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }, host: '1.2.3.4')
    packet.pdu_header.pfc_flags.object_uuid = 1
    packet.object = '8a885d04-1ceb-11c9-9fe8-08002b104860'
    packet.auth_verifier = '123456'
    packet.pdu_header.auth_length = 6
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

