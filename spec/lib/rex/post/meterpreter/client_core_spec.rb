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

end
