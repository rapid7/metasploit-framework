require 'spec_helper'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/priv/priv'

RSpec.describe Rex::Post::Meterpreter::Extensions::Priv::Priv do

  it "should be available" do
    expect(described_class).to eq(Rex::Post::Meterpreter::Extensions::Priv::Priv)
  end

  describe "#getsystem" do
    before(:example) do
      @client = double("client")
      allow(@client).to receive(:register_extension_aliases) { [] }
    end

    let(:priv) {described_class.new(@client)}
    it 'should respond to #getsystem' do
      expect(priv).to respond_to(:getsystem)
    end

    it 'should return itself' do
      expect(priv).to be_kind_of(described_class)
    end

    it 'should have some instance variables' do
      expect(priv.instance_variables).to include(:@client)
      expect(priv.instance_variables).to include(:@name)
      expect(priv.instance_variables).to include(:@fs)
    end

    it 'should respond to fs' do
      expect(priv).to respond_to(:fs)
    end

    it 'should have a name of priv' do
      expect(priv.name).to eq("priv")
    end

  end
end
