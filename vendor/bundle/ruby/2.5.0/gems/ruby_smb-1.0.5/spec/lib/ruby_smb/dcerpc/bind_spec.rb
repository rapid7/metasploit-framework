RSpec.describe RubySMB::Dcerpc::Bind do
  let(:uuid) { '12345678-1234-4321-5678-123456789012' }
  let(:ver_major) { 2 }
  let(:ver_minor) { 8 }
  let :endpoint do
    endpoint = Module.new
    endpoint.const_set('UUID', uuid)
    endpoint.const_set('VER_MAJOR', ver_major)
    endpoint.const_set('VER_MINOR', ver_minor)
    endpoint
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdu_header }
  it { is_expected.to respond_to :max_xmit_frag }
  it { is_expected.to respond_to :max_recv_frag }
  it { is_expected.to respond_to :assoc_group_id }
  it { is_expected.to respond_to :p_context_list }
  it { is_expected.to respond_to :auth_verifier }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#pdu_header' do
    subject(:header) { packet.pdu_header }

    it 'is a standard PDU Header' do
      expect(header).to be_a RubySMB::Dcerpc::PDUHeader
    end

    it 'should have the #ptype field set to PTypes::BIND' do
      expect(header.ptype).to eq RubySMB::Dcerpc::PTypes::BIND
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

  describe '#p_context_list' do
    it 'should be a PContListT structure' do
      expect(packet.p_context_list).to be_a RubySMB::Dcerpc::PContListT
    end

    it 'should have an #endpoint parameter' do
      expect(packet.p_context_list.has_parameter?(:endpoint)).to be true
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
    packet = described_class.new(endpoint: endpoint)
    packet.auth_verifier = '123456'
    packet.pdu_header.auth_length = 6
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe RubySMB::Dcerpc::PContListT do
  let(:uuid) { '12345678-1234-4321-5678-123456789012' }
  let(:ver_major) { 2 }
  let(:ver_minor) { 8 }
  let :endpoint do
    endpoint = Module.new
    endpoint.const_set('UUID', uuid)
    endpoint.const_set('VER_MAJOR', ver_major)
    endpoint.const_set('VER_MINOR', ver_minor)
    endpoint
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :n_context_elem }
  it { is_expected.to respond_to :p_cont_elem }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#n_context_elem' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.n_context_elem).to be_a BinData::Uint8
    end

    it 'should have the default value 1' do
      expect(packet.n_context_elem).to eq 1
    end
  end

  describe '#p_cont_elem' do
    it 'should be an array of type PContElemT' do
      expect(packet.p_cont_elem).to be_a BinData::Array
      type = packet.p_cont_elem.get_parameter(:type)
      expect(type.instantiate).to be_a RubySMB::Dcerpc::PContElemT
    end

    it 'should have #n_context_elem elements' do
      n_elements = 4
      packet.n_context_elem = n_elements
      expect(packet.p_cont_elem.size).to eq n_elements
    end

    it 'should have an #endpoint parameter' do
      expect(packet.p_cont_elem.has_parameter?(:endpoint)).to be true
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new(endpoint: endpoint)
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe RubySMB::Dcerpc::PContElemT do
  let(:uuid) { '12345678-1234-4321-5678-123456789012' }
  let(:ver_major) { 2 }
  let(:ver_minor) { 8 }
  let :endpoint do
    endpoint = Module.new
    endpoint.const_set('UUID', uuid)
    endpoint.const_set('VER_MAJOR', ver_major)
    endpoint.const_set('VER_MINOR', ver_minor)
    endpoint
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :p_cont_id }
  it { is_expected.to respond_to :n_transfer_syn }
  it { is_expected.to respond_to :abstract_syntax }
  it { is_expected.to respond_to :transfer_syntaxes }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#p_cont_id' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.p_cont_id).to be_a BinData::Uint16le
    end
  end

  describe '#n_transfer_syn' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.n_transfer_syn).to be_a BinData::Uint8
    end

    it 'should have the default value 1' do
      expect(packet.n_transfer_syn).to eq 1
    end
  end

  describe '#abstract_syntax' do
    it 'should be a PSyntaxIdT structure' do
      expect(packet.abstract_syntax).to be_a RubySMB::Dcerpc::PSyntaxIdT
    end

    it 'should have an #uuid parameter' do
      expect(packet.abstract_syntax.has_parameter?(:uuid)).to be true
    end

    it 'should have a #ver_major parameter' do
      expect(packet.abstract_syntax.has_parameter?(:ver_major)).to be true
    end

    it 'should have a #ver_minor parameter' do
      expect(packet.abstract_syntax.has_parameter?(:ver_minor)).to be true
    end

    it 'should be initialized with the #endpoint constants' do
      p_cont_elem_t = described_class.new(endpoint: endpoint)

      expect(p_cont_elem_t.abstract_syntax.if_uuid).to eq(uuid)
      expect(p_cont_elem_t.abstract_syntax.if_ver_major).to eq(ver_major)
      expect(p_cont_elem_t.abstract_syntax.if_ver_minor).to eq(ver_minor)
    end

    it 'should be initialized with the #endpoint constants when passed as a parameter to Bind' do
      bind = RubySMB::Dcerpc::Bind.new(endpoint: endpoint)
      p_cont_elem_t = bind.p_context_list.p_cont_elem.first

      expect(p_cont_elem_t.abstract_syntax.if_uuid).to eq(uuid)
      expect(p_cont_elem_t.abstract_syntax.if_ver_major).to eq(ver_major)
      expect(p_cont_elem_t.abstract_syntax.if_ver_minor).to eq(ver_minor)
    end
  end

  describe '#transfer_syntaxes' do
    it 'should be an array of type PSyntaxIdT' do
      expect(packet.transfer_syntaxes).to be_a BinData::Array
      type = packet.transfer_syntaxes.get_parameter(:type)
      expect(type.instantiate).to be_a RubySMB::Dcerpc::PSyntaxIdT
    end

    it 'should have #n_transfer_syn elements' do
      n_elements = 4
      packet.n_transfer_syn = n_elements
      expect(packet.transfer_syntaxes.size).to eq n_elements
    end

    it 'sets its elements to the NDR presentation syntax' do
      expect(packet.transfer_syntaxes[0].if_uuid).to eq RubySMB::Dcerpc::Ndr::UUID
      expect(packet.transfer_syntaxes[0].if_ver_major).to eq RubySMB::Dcerpc::Ndr::VER_MAJOR
      expect(packet.transfer_syntaxes[0].if_ver_minor).to eq RubySMB::Dcerpc::Ndr::VER_MINOR
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new(endpoint: endpoint)
    packet.n_transfer_syn = 2
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
