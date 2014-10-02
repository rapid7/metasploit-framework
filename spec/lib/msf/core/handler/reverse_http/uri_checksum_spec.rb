require 'spec_helper'
require 'msf/core/handler/reverse_http/uri_checksum'

describe Msf::Handler::ReverseHttp::UriChecksum do
   class DummyClass
     include Msf::Handler::ReverseHttp::UriChecksum
   end

  subject(:dummy_object) { DummyClass.new }

  it { should respond_to :generate_uri_checksum}
  it { should respond_to :process_uri_resource}

  describe '#generate_uri_checksum' do
    let(:checksum_value) { 92 }
    let(:expected_length) { 6 }

    it 'generates a string that checksums back to the original value' do
      uri_string = dummy_object.generate_uri_checksum(checksum_value)
      expect(Rex::Text.checksum8(uri_string)).to eq checksum_value
    end
    
    it 'generates a string that has the correct length' do
      uri_string = dummy_object.generate_uri_checksum(checksum_value, expected_length)
      expect(uri_string.length).to eq expected_length
    end
    
    it 'generates an exception when passed a negative length' do
      expect { dummy_object.generate_uri_checksum(checksum_value, -1) }.to raise_error(ArgumentError)
    end
    
    it 'generates an exception when passed an invalid checksum' do
      expect { dummy_object.generate_uri_checksum(256) }.to raise_error(ArgumentError)
    end
    
    it 'generates an exception when it does not find a result' do
      expect { dummy_object.generate_uri_checksum(2,1) }.to raise_error(RuntimeError)
    end
  end

  describe '#process_uri_resource' do
    context 'when passed a value for INITW' do
      let(:uri) { "/7E37v"}

      it 'returns a static value of /INITM' do
        expect(dummy_object.process_uri_resource(uri)).to eq '/INITM'
      end

      context 'with junk appended at the end' do
        let(:uri) { "/7E37v_foobar"}

        it 'returns a static value of /INITM' do
          expect(dummy_object.process_uri_resource(uri)).to eq '/INITM'
        end
      end
    end

    context 'when passed a value for INITJ' do
      let(:uri) { "/a6BF9"}

      it 'returns a static value of /INITJM' do
        expect(dummy_object.process_uri_resource(uri)).to eq '/INITJM'
      end

      context 'with junk appended at the end' do
        let(:uri) { "/a6BF9_foobar"}

        it 'returns a static value of /INITJM' do
          expect(dummy_object.process_uri_resource(uri)).to eq '/INITJM'
        end
      end
    end

    context 'when passed a value for CONN' do
      let(:uri) { "/39ab3"}

      it 'returns /CONN plus random junk' do
        expect(dummy_object.process_uri_resource(uri)).to match(/\/CONN_(\w){16}/)
      end

      context 'with junk appended at the end' do
        let(:uri) { "/39ab3_foobar"}

        it 'returns /CONN plus the junk' do
          expect(dummy_object.process_uri_resource(uri)).to eq '/CONN_foobar'
        end
      end
    end

    context 'when passed a junk value' do
      let(:uri) { "/lolz"}

      it 'returns the original uri string' do
        expect(dummy_object.process_uri_resource(uri)).to eq '/lolz'
      end
    end
  end

end
