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

    it 'requests the full path of a method with several segments' do
      expect(client).to receive(:send_request).with('custom/device/reset').once.and_return({})

      extension.send_request('reset', [], [{ 'method_name' => 'custom/device/reset', 'args' => [] }])
    end

    it 'does not match a method whose earlier segment equals the command' do
      expect(client).not_to receive(:send_request)

      extension.send_request('device', [], [{ 'method_name' => 'custom/device/reset', 'args' => [] }])
    end

    it 'passes arguments as a query string' do
      expect(client).to receive(:send_request).with('custom/lock?a=1&b=2').and_return({})

      extension.send_request('lock', ['a=1', 'b=2'], methods)
    end

    it 'escapes argument values instead of creating additional parameters or requests' do
      expect(client).to receive(:send_request).with('custom/lock?data=a%26mode%3Db%0D%0A').and_return({})

      extension.send_request('lock', ["data=a&mode=b\r\n"], methods)
    end

    it 'requests a root-level route' do
      expect(client).to receive(:send_request).with('temperature').and_return({})

      extension.send_request('temperature', [], [{ 'method_name' => 'temperature' }])
    end

    it 'rejects a route with injected HTTP request lines' do
      expect(client).not_to receive(:send_request)

      result = extension.send_request('lock', [], [{ 'method_name' => "custom/x HTTP/1.1\r\n\r\nGET /lock" }])
      expect(result).to eq('success' => false)
    end

    it 'rejects ambiguous command names instead of sending multiple requests' do
      expect(client).not_to receive(:send_request)

      result = extension.send_request('lock', [], [{ 'method_name' => 'a/lock' }, { 'method_name' => 'b/lock' }])
      expect(result).to include('success' => false, 'status' => 'Ambiguous custom method name')
    end

    context 'when the reply is not a hash' do
      let(:methods) { [{ 'method_name' => 'custom/lock', 'args' => [] }] }

      [nil, [1, 2], 'unexpected', 42, true].each do |reply|
        context "when the reply is #{reply.inspect}" do
          before { allow(client).to receive(:send_request).and_return(reply) }

          it 'does not raise' do
            expect { extension.send_request('lock', [], methods) }.not_to raise_error
          end

          it 'reports a failure' do
            expect(extension.send_request('lock', [], methods)).to include('success' => false)
          end

          it 'explains that the reply was unexpected' do
            expect(extension.send_request('lock', [], methods)['status']).to match(/Unexpected or missing reply/)
          end
        end
      end
    end

    context 'when a method declares a return type' do
      def reply_value(return_type, value)
        allow(client).to receive(:send_request).and_return({ 'value' => value })

        extension.send_request('lock', [], [{ 'method_name' => 'custom/lock', 'args' => [], 'return' => return_type }])['value']
      end

      it 'converts an int' do
        expect(reply_value('int', '42')).to eq(42)
      end

      it 'converts a float' do
        expect(reply_value('float', '1.5')).to eq(1.5)
      end

      it 'converts an integer to hex' do
        expect(reply_value('hex', 255)).to eq('0xff')
      end

      it 'converts the string true to a boolean true' do
        expect(reply_value('boolean', 'true')).to be true
      end

      it 'converts any other boolean value to false' do
        expect(reply_value('boolean', 'no')).to be false
      end

      it 'returns a hex value that is not an integer unchanged' do
        expect(reply_value('hex', '255')).to eq('255')
      end

      it 'returns an int value that cannot be converted unchanged' do
        expect(reply_value('int', [1])).to eq([1])
      end

      it 'returns a float value that cannot be converted unchanged' do
        expect(reply_value('float', { 'a' => 1 })).to eq({ 'a' => 1 })
      end

      it 'returns the value unchanged for an unknown return type' do
        expect(reply_value('mystery', 'abc')).to eq('abc')
      end
    end

    context 'when the method matches no route' do
      it 'reports a failure without contacting the hardware' do
        expect(client).not_to receive(:send_request)

        expect(extension.send_request('missing', [], methods)).to eq('success' => false)
      end
    end
  end
end
