require 'rex'
require 'msf/util/java_deserialization'

RSpec.describe Msf::Util::JavaDeserialization do
  let(:payload_name) do
    'PAYLOAD_NAME'
  end

  let(:default_command) do
    nil
  end

  describe '#ysoserial_payload' do
    context 'when default payload name is changed' do
      it 'raises a RuntimeError' do
        payload_filename_constant = Msf::Util::JavaDeserialization.const_get(:PAYLOAD_FILENAME)
        Msf::Util::JavaDeserialization.const_set(:PAYLOAD_FILENAME, 'INVALID')
        expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(RuntimeError)
        Msf::Util::JavaDeserialization.const_set(:PAYLOAD_FILENAME, payload_filename_constant)
      end
    end

    context 'when default payload is not found' do
      it 'raises a RuntimeError' do
        allow(File).to receive(:join).and_return('INVALID')
        expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(RuntimeError)
      end
    end

    context 'when default payload is not JSON format' do
      it 'raises a RuntimeError error' do
        allow(File).to receive(:read).and_return('BAD DATA')
        expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(RuntimeError)
      end
    end

    context 'when payload status is unsupported' do
      it 'raises a unsupported error' do
        json_data = %Q|{"BeanShell1":{"status":"unsupported","bytes":"AAAA"}}|
        allow(File).to receive(:read).and_return(json_data)
        expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(ArgumentError)
      end
    end

    context 'when payload status is static' do
      let(:payload_name) do
        'BeanShell1'
      end

      it 'returns a Base64 string' do
        original_bytes = 'AAAA'
        b64 = Rex::Text.encode_base64(original_bytes)
        json_data = %Q|{"BeanShell1":{"status":"static","bytes":"#{b64}"}}|
        allow(File).to receive(:read).and_return(json_data)
        p = Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)
        expect(p).to eq(original_bytes)
      end
    end

    context 'when payload status is dynamic' do
      let(:payload_name) do
        'BeanShell1'
      end

      context 'when missing a command' do
        it 'raises an argument error' do
          expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(ArgumentError)
        end
      end

      context 'when a command is provided' do
        it 'returns serialized data' do
          default_command = 'id'
          p = Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)
          expect(p).to include('java.awt.event')
        end
      end
    end
  end
end
