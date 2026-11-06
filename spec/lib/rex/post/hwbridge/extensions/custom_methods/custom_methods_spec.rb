require 'rex'
require 'rex/post/hwbridge/extensions/custom_methods/custom_methods'

RSpec.describe Rex::Post::HWBridge::Extensions::CustomMethods::CustomMethods do
  let(:client) { double('client', register_extension_aliases: nil) }

  subject(:extension) { described_class.new(client) }

  describe '#send_request' do
    let(:methods) do
      [
        { 'method_name' => 'custom/lock', 'args' => [] },
        { 'method_name' => 'custom/unlock', 'args' => [] }
      ]
    end

    it 'requests only the route whose final segment is the command' do
      expect(client).to receive(:send_request).with('custom/lock').once.and_return({})

      extension.send_request('lock', [], methods)
    end

    it 'requests the unlock route for unlock' do
      expect(client).to receive(:send_request).with('custom/unlock').once.and_return({})

      extension.send_request('unlock', [], methods)
    end

    it 'passes arguments as a query string' do
      expect(client).to receive(:send_request).with('custom/lock?a=1&b=2').and_return({})

      extension.send_request('lock', ['a=1', 'b=2'], methods)
    end
  end
end
