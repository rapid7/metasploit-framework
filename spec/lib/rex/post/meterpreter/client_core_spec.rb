require 'spec_helper'
require 'rex/post/meterpreter/client_core'

RSpec.describe Rex::Post::Meterpreter::ClientCore do

  it "should be available" do
    expect(described_class).to eq(Rex::Post::Meterpreter::ClientCore)
  end

  describe "#use" do

    before(:example) do
      @response = double("response")
      allow(@response).to receive(:result) { 0 }
      allow(@response).to receive(:each) { [:help] }
      @client = double("client")
      allow(@client).to receive(:binary_suffix) { ["x64.dll"] }
      allow(@client).to receive(:capabilities) { {:ssl => false, :zlib => false } }
      allow(@client).to receive(:response_timeout) { 1 }
      allow(@client).to receive(:send_packet_wait_response) { @response }
      allow(@client).to receive(:add_extension) { true }
      allow(@client).to receive(:debug_build) { false }
    end

    let(:client_core) {described_class.new(@client)}
    it 'should respond to #use' do
      expect(client_core).to respond_to(:use)
    end

    context 'with a gemified module' do
      let(:mod) {"kiwi"}
      it 'should be available' do
        expect(client_core.use(mod)).to be_truthy
      end
    end

    context 'with a local module' do
      let(:mod) {"sniffer"}
      it 'should be available' do
        expect(client_core.use(mod)).to be_truthy
      end
    end

    context 'with a missing a module' do
      let(:mod) {"eaten_by_av"}
      it 'should be available' do
        expect { client_core.use(mod) }.to raise_error(RuntimeError)
      end
    end


  end

  describe '#micro_has_commands' do
    let(:client) { double('client') }
    let(:client_core) { described_class.new(client) }
    let(:present_command_id) { 1009 }
    let(:absent_command_id) { 1016 }
    let(:response) { double('response') }

    it 'returns availability for multiple command IDs in one request' do
      allow(response).to receive(:get_tlvs).with(TLV_TYPE_UINT) do
        [double('tlv', value: present_command_id)]
      end
      allow(client).to receive(:send_request) do |request|
        expect(request.method).to eq(COMMAND_ID_CORE_MICRO_HAS_COMMAND)
        expect(request.get_tlvs(TLV_TYPE_UINT).map(&:value)).to eq(
          [present_command_id, absent_command_id]
        )
        response
      end

      expect(client_core.micro_has_commands(present_command_id, absent_command_id)).to eq(
        present_command_id => true,
        absent_command_id => false
      )
    end
  end

  describe '#micro_load' do
    let(:client) { double('client', capabilities: { zlib: false }, response_timeout: 1) }
    let(:client_core) { described_class.new(client) }
    let(:response) { double('response') }

    it 'loads a named object and returns its remote metadata' do
      allow(response).to receive(:get_tlv_value).with(TLV_TYPE_MICRO_HANDLE).and_return(7)
      allow(response).to receive(:get_tlvs).with(TLV_TYPE_UINT).and_return([double('tlv', value: 1059)])
      allow(response).to receive(:get_tlvs).with(TLV_TYPE_CHANNEL_TYPE).and_return([double('tlv', value: 'stdapi_fs_file')])
      allow(response).to receive(:result).and_return(0)
      allow(client).to receive(:send_packet_wait_response) do |request, _timeout|
        expect(request.method).to eq(COMMAND_ID_CORE_MICRO_LOAD)
        expect(request.get_tlv_value(TLV_TYPE_MICRO_NAME)).to eq('micro-stdapi-sysinfo')
        expect(request.get_tlv_value(TLV_TYPE_MICRO_IMAGE)).to eq('coff')
        response
      end

      expect(client_core.micro_load('micro-stdapi-sysinfo', 'coff')).to eq(handle: 7, commands: [1059], channels: ['stdapi_fs_file'])
    end
  end

  describe '#micro_extensions' do
    let(:client) { double('client') }
    let(:client_core) { described_class.new(client) }
    let(:response) { Packet.create_response(Packet.create_request(COMMAND_ID_CORE_MICRO_ENUM)) }

    it 'returns loaded objects' do
      entry = response.add_tlv(TLV_TYPE_MICRO_ENTRY)
      entry.add_tlv(TLV_TYPE_MICRO_NAME, 'micro-stdapi-sysinfo')
      entry.add_tlv(TLV_TYPE_MICRO_HANDLE, 7)
      entry.add_tlv(TLV_TYPE_MICRO_ABI, 1)
      entry.add_tlv(TLV_TYPE_UINT, 1059)
      entry.add_tlv(TLV_TYPE_CHANNEL_TYPE, 'stdapi_fs_file')
      allow(client).to receive(:send_request).and_return(response)

      expect(client_core.micro_extensions).to eq([{ name: 'micro-stdapi-sysinfo', handle: 7, abi: 1, commands: [1059], channels: ['stdapi_fs_file'] }])
    end
  end

  describe '#micro_command_ids' do
    let(:client_core) { described_class.new(double('client')) }

    it 'returns only commands from the microextension inventory' do
      allow(client_core).to receive(:micro_extensions).and_return(
        [
          { name: 'first', handle: 1, abi: 1, commands: [1009, 1016] },
          { name: 'second', handle: 2, abi: 1, commands: [1016, 1059] }
        ]
      )

      expect(client_core.micro_command_ids).to eq([1009, 1016, 1059])
    end
  end

  describe '#micro_channel_types' do
    let(:client_core) { described_class.new(double('client')) }

    it 'returns only channel types from the microextension inventory' do
      allow(client_core).to receive(:micro_extensions).and_return(
        [
          { name: 'first', handle: 1, abi: 2, commands: [], channels: ['stdapi_fs_file'] },
          { name: 'second', handle: 2, abi: 2, commands: [], channels: ['stdapi_fs_file', 'example'] }
        ]
      )

      expect(client_core.micro_channel_types).to eq(['stdapi_fs_file', 'example'])
    end
  end

  describe '#micro_unload' do
    let(:client) { double('client') }
    let(:client_core) { described_class.new(client) }
    let(:response) { double('response') }

    it 'unloads by handle and returns removed commands' do
      allow(response).to receive(:get_tlvs).with(TLV_TYPE_UINT).and_return([double('tlv', value: 1059)])
      allow(response).to receive(:get_tlvs).with(TLV_TYPE_CHANNEL_TYPE).and_return([double('tlv', value: 'stdapi_fs_file')])
      allow(client).to receive(:send_request) do |request|
        expect(request.method).to eq(COMMAND_ID_CORE_MICRO_UNLOAD)
        expect(request.get_tlv_value(TLV_TYPE_MICRO_HANDLE)).to eq(7)
        response
      end

      expect(client_core.micro_unload(7)).to eq(commands: [1059], channels: ['stdapi_fs_file'])
    end
  end

end
