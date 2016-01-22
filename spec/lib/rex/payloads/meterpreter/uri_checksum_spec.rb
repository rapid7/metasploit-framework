require 'spec_helper'
require 'rex/payloads/meterpreter/uri_checksum'

RSpec.describe Rex::Payloads::Meterpreter::UriChecksum do
   class DummyClass
     include Rex::Payloads::Meterpreter::UriChecksum
   end

  subject(:dummy_object) { DummyClass.new }

  it { is_expected.to respond_to :generate_uri_checksum}
  it { is_expected.to respond_to :process_uri_resource}
  it { is_expected.to respond_to :uri_checksum_lookup}

  describe '#process_uri_resource' do
    context 'when passed a value for INITW' do
      let(:uri) { "/7E37v"}

      it 'returns a static value of /INITM' do
        expect(dummy_object.process_uri_resource(uri)[:mode]).to eq :init_native
      end

      context 'with junk appended at the end' do
        let(:uri) { "/7E37v_foobar"}

        it 'returns a static value of /INITM' do
          expect(dummy_object.process_uri_resource(uri)[:mode]).to eq nil
        end
      end
    end

    context 'when passed a value for INITJ' do
      let(:uri) { "/a6BF9"}

      it 'returns a static value of /INITJM' do
        expect(dummy_object.process_uri_resource(uri)[:mode]).to eq :init_java
      end

      context 'with junk appended at the end' do
        let(:uri) { "/a6BF9_foobar"}

        it 'returns a static value of /INITJM' do
          expect(dummy_object.process_uri_resource(uri)[:mode]).to eq nil
        end
      end
    end

    context 'when passed a value for CONN' do
      let(:uri) { "/39ab3"}

      it 'returns /CONN plus random junk' do
        expect(dummy_object.process_uri_resource(uri)[:mode]).to eq :connect
      end

      context 'with junk appended at the end' do
        let(:uri) { "/39ab3_foobar"}

        it 'returns /CONN plus the junk' do
          expect(dummy_object.process_uri_resource(uri)[:mode]).to eq nil
        end
      end
    end

    context 'when passed a junk value' do
      let(:uri) { "/lolz"}

      it 'returns the original uri string' do
        expect(dummy_object.process_uri_resource(uri)[:mode]).to eq nil
      end
    end
  end

  describe '#generate_uri_checksum' do
    [0, 80, 88, 90, 92, 98, 255, 127].each do |checksum_value|
      [5,30,50,100,127].each do |uri_length|
        ["", "/boom", "/___AAAAAAAAAAAAA"].each do |prefix|
          it "generates a #{uri_length} byte string that checksums back to the original value (#{checksum_value}) with prefix #{prefix}" do
            uri_string = dummy_object.generate_uri_checksum(checksum_value, uri_length + prefix.to_s.length, prefix)
            expect(Rex::Text.checksum8(uri_string)).to eq checksum_value
          end
        end
      end
    end
  end

  describe '#uri_checksum_lookup' do

    context 'when passed a value for :connect' do
      let(:mode) { :connect }
      it 'returns a URI_CHECKSUM_CONN' do
        expect(dummy_object.uri_checksum_lookup(mode)).to eq Rex::Payloads::Meterpreter::UriChecksum::URI_CHECKSUM_CONN
      end
    end

    context 'when passed a value for :init_native' do
      let(:mode) { :init_native }
      it 'returns a URI_CHECKSUM_INITN' do
        expect(dummy_object.uri_checksum_lookup(mode)).to eq Rex::Payloads::Meterpreter::UriChecksum::URI_CHECKSUM_INITN
      end
    end

    context 'when passed a value for :init_java' do
      let(:mode) { :init_java }
      it 'returns a URI_CHECKSUM_INITJ' do
        expect(dummy_object.uri_checksum_lookup(mode)).to eq Rex::Payloads::Meterpreter::UriChecksum::URI_CHECKSUM_INITJ
      end
    end

    context 'when passed a value for :init_python' do
      let(:mode) { :init_python }
      it 'returns a URI_CHECKSUM_INITP' do
        expect(dummy_object.uri_checksum_lookup(mode)).to eq Rex::Payloads::Meterpreter::UriChecksum::URI_CHECKSUM_INITP
      end
    end

  end

end
