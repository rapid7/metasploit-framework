require 'spec_helper'
require 'rex/post/meterpreter'
require 'rex/post/meterpreter/extensions/stdapi/ui'

RSpec.describe Rex::Post::Meterpreter::Extensions::Stdapi::UI do

  it "should be available" do
    expect(described_class).to eq(Rex::Post::Meterpreter::Extensions::Stdapi::UI)
  end

  describe "#screenshot" do

    before(:example) do
      @client = double("client")
    end

    let(:ui) { described_class.new(@client) }
    it 'should respond to #screenshot' do
      expect(ui).to respond_to(:screenshot)
    end

    it 'should return itself' do
      expect(ui).to be_kind_of(described_class)
    end

    it 'should have an instance variable' do
      expect(ui.instance_variables).to include(:@client)
    end

  end

end

