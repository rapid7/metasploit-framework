require 'rex'

RSpec.describe Msf::Util::JavaDeserialization do
  let(:payload_name) do
    'PAYLOAD_NAME'
  end

  let(:default_command) do
    nil
  end
  describe '#ysoserial_payload' do

    context 'when default payload is not found' do
      it 'raises a RuntimeError' do
        stub_const('Msf::Util::JavaDeserialization::PAYLOAD_FILENAME', 'INVALID')
        expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(RuntimeError, /Unable to load JSON data from:/)
      end
    end

    context 'when default payload is not JSON format' do
      it 'raises a RuntimeError error' do
        allow(File).to receive(:read).and_return('BAD DATA')
        expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(RuntimeError, /Unable to load JSON data from:/)
      end
    end

    context 'when payload status is unsupported' do
      it 'raises a unsupported error' do
        json_data = %Q|{"none":{"BeanShell1":{"status":"unsupported","bytes":"AAAA"}}}|
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
        json_data = %Q|{"none":{"BeanShell1":{"status":"static","bytes":"#{b64}"}}}|
        allow(File).to receive(:read).and_return(json_data)
        p = Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)
        expect(p).to eq(original_bytes)
      end
    end

    context 'when payload status is dynamic' do
      let(:payload_name) do
        'CommonsCollections1'
      end

      context 'when missing a command' do
        it 'raises an argument error' do
          expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)}.to raise_error(ArgumentError)
        end
      end

      context 'when a modified type is not found' do
        it 'raises an argument error' do
          type = 'unknown_type'
          expect{Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command, modified_type: type)}.to raise_error(ArgumentError)
        end
      end

      context 'when a command is provided' do
        it 'returns serialized data' do
          default_command = 'id'
          p = Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command)
          expect(p).to include('java.util.Mapxr')
        end
      end

      context 'when command and type are provided' do
        it 'returns serialized data' do
          default_command = 'id'
          type = 'bash'
          p = Msf::Util::JavaDeserialization::ysoserial_payload(payload_name, default_command, modified_type: type)
          expect(p).to include('java.util.Mapxr')
        end
      end
    end
  end
end
