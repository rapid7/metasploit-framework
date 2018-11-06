RSpec.describe RubySMB::Dcerpc::BindAck do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdu_header }
  it { is_expected.to respond_to :max_xmit_frag }
  it { is_expected.to respond_to :max_recv_frag }
  it { is_expected.to respond_to :assoc_group_id }
  it { is_expected.to respond_to :sec_addr }
  it { is_expected.to respond_to :p_result_list }
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
      expect(header.ptype).to eq RubySMB::Dcerpc::PTypes::BIND_ACK
    end
  end

  describe '#max_xmit_frag' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.max_xmit_frag).to be_a BinData::Uint16le
    end

    it 'should have a default value of 0xFFFF' do
      expect(packet.max_xmit_frag).to eq 0xFFFF
    end
  end

  describe '#max_recv_frag' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.max_recv_frag).to be_a BinData::Uint16le
    end

    it 'should have a default value of 0xFFFF' do
      expect(packet.max_recv_frag).to eq 0xFFFF
    end
  end

  describe '#assoc_group_id' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.assoc_group_id).to be_a BinData::Uint32le
    end
  end

  describe '#pad' do
    it 'should keep #p_result_list 4-byte aligned' do
      packet.sec_addr.port_spec = "test"
      expect(packet.p_result_list.abs_offset % 4).to eq 0
    end
  end

  describe '#p_result_list' do
    it 'should be a PContListT structure' do
      expect(packet.p_result_list).to be_a RubySMB::Dcerpc::PResultListT
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

  describe '#pad_length' do
    it 'returns 0 when #p_result_list is already 4-byte aligned' do
      packet.sec_addr.port_spec = 'align'
      expect(packet.pad_length).to eq 0
    end

    it 'returns 2 when #p_result_list is only 2-byte aligned' do
      packet.sec_addr.port_spec = 'align' + 'AA'
      expect(packet.pad_length).to eq 2
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet.sec_addr.port_spec = "port spec"
    packet.p_result_list.n_results = 2
    packet.auth_verifier = '123456'
    packet.pdu_header.auth_length = 6
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe RubySMB::Dcerpc::PortAnyT do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :str_length }
  it { is_expected.to respond_to :port_spec }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#str_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.str_length).to be_a BinData::Uint16le
    end

    it 'should be the size of #port_spec string, including the NULL terminator' do
      str = 'test'
      packet.port_spec = str
      expect(packet.str_length).to eq(str.size + 1)
    end
  end

  describe '#port_spec' do
    it 'should be a Stringz' do
      expect(packet.port_spec).to be_a BinData::Stringz
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet.port_spec = "port spec"
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe RubySMB::Dcerpc::PResultListT do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :n_results }
  it { is_expected.to respond_to :p_results }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#n_results' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.n_results).to be_a BinData::Uint8
    end
  end

  describe '#p_results' do
    it 'should be an array of type PResultT' do
      expect(packet.p_results).to be_a BinData::Array
      type = packet.p_results.get_parameter(:type)
      expect(type.instantiate).to be_a RubySMB::Dcerpc::PResultT
    end

    it 'should have #n_results elements' do
      n_elements = 4
      packet.n_results = n_elements
      expect(packet.p_results.size).to eq n_elements
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet.n_results = 4
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe RubySMB::Dcerpc::PResultT do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :result }
  it { is_expected.to respond_to :reason }
  it { is_expected.to respond_to :transfer_syntax }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#result' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.result).to be_a BinData::Uint16le
    end
  end

  describe '#reason' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.reason).to be_a BinData::Uint16le
    end
  end

  describe '#transfer_syntax' do
    it 'should be a PSyntaxIdT' do
      expect(packet.transfer_syntax).to be_a RubySMB::Dcerpc::PSyntaxIdT
    end

    it 'is set to the NDR presentation syntax' do
      expect(packet.transfer_syntax.if_uuid).to eq RubySMB::Dcerpc::Ndr::UUID
      expect(packet.transfer_syntax.if_ver_major).to eq RubySMB::Dcerpc::Ndr::VER_MAJOR
      expect(packet.transfer_syntax.if_ver_minor).to eq RubySMB::Dcerpc::Ndr::VER_MINOR
    end
  end

  it 'reads its own binary representation and output the same packet' do
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

