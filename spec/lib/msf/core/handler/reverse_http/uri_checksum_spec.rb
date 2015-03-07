require 'spec_helper'
require 'msf/core/handler/reverse_http/uri_checksum'

describe Msf::Handler::ReverseHttp::UriChecksum do
   class DummyClass
     include Msf::Handler::ReverseHttp::UriChecksum
   end

  subject(:dummy_object) { DummyClass.new }

  it { should respond_to :generate_uri_checksum}
  it { should respond_to :generate_uri_checksum_with_length}
  it { should respond_to :process_uri_resource}

  describe '#generate_uri_checksum' do
    let(:checksum_value) { 92 }

    it 'generates a string that checksums back to the original value' do
      uri_string = dummy_object.generate_uri_checksum(checksum_value)
      expect(Rex::Text.checksum8(uri_string)).to eq checksum_value
    end

    context 'when it fails to generate a random URI' do
      it 'should use the pre-calculated checksum string' do
        Rex::Text.stub(:checksum8) { false }
        expect(dummy_object.generate_uri_checksum(checksum_value)).to eq Msf::Handler::ReverseHttp::UriChecksum::URI_CHECKSUM_PRECALC[checksum_value]
      end

    end
  end

  describe '#generate_uri_checksum_with_length' do
    [0, 80, 88, 90, 92, 98, 255, 127].each do |checksum_value|
      [5,30,50,100,127].each do |uri_length|
        it "generates a #{uri_length} byte string that checksums back to the original value (#{checksum_value})" do
          uri_string = dummy_object.generate_uri_checksum_with_length(checksum_value, uri_length)
          expect(Rex::Text.checksum8(uri_string)).to eq checksum_value
        end
      end
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
