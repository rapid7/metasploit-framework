# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Payload::MalleableC2 do
  let(:fixture_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures', 'malleable_c2') }

  describe Msf::Payload::MalleableC2::Parser do
    subject(:parser) { described_class.new }

    describe '#parse' do
      context 'with minimal_uris_headers.profile' do
        it 'returns a ParsedProfile without raising' do
          path = File.join(fixture_path, 'minimal_uris_headers.profile')
          result = parser.parse(path)
          expect(result).to be_a(Msf::Payload::MalleableC2::ParsedProfile)
        end
      end

      context 'with base64_transforms.profile' do
        it 'returns a ParsedProfile without raising' do
          path = File.join(fixture_path, 'base64_transforms.profile')
          result = parser.parse(path)
          expect(result).to be_a(Msf::Payload::MalleableC2::ParsedProfile)
        end
      end

      context 'with a non-existent path' do
        it 'raises an exception' do
          expect {
            parser.parse('/nonexistent/path.profile')
          }.to raise_error(Exception)
        end
      end
    end

    describe 'ParsedProfile#uris' do
      it 'returns the URIs declared in minimal_uris_headers.profile' do
        path = File.join(fixture_path, 'minimal_uris_headers.profile')
        profile = parser.parse(path)
        expect(profile.uris).to contain_exactly('/jquery-3.3.1.min.js', '/jquery-3.3.1.min.js/save')
      end
    end

    describe 'ParsedProfile#to_tlv' do
      context 'with minimal_uris_headers.profile' do
        subject(:profile) do
          parser.parse(File.join(fixture_path, 'minimal_uris_headers.profile'))
        end

        it 'does not emit a static query string for single-arg metadata parameter directives' do
          # The profile declares `metadata { parameter "callback"; }` — this is a UUID
          # placement directive (the payload fills in the UUID at runtime), not a static
          # key=value query param. It must NOT appear as "callback=" in the emitted URI TLV,
          # otherwise the PHP payload sends GET /path?callback= (empty) on every poll,
          # which the handler cannot map to a session and channel reads block forever.
          tlv = profile.to_tlv
          get_tlv = tlv.tlvs.find { |t| t.type == Msf::Payload::MalleableC2::MET::TLV_TYPE_C2_GET }
          uri_tlvs = get_tlv.tlvs.select { |t| t.type == Msf::Payload::MalleableC2::MET::TLV_TYPE_C2_URI }
          uri_tlvs.each do |uri_tlv|
            expect(uri_tlv.value).not_to include('callback='),
              "GET URI '#{uri_tlv.value}' contains 'callback=' — single-arg parameter directives " \
              "must not be emitted as static query string parameters"
          end
        end

        it 'does not emit a static query string for single-arg id parameter directives' do
          # Similarly, `id { parameter "id"; }` in http-post is a placement directive.
          tlv = profile.to_tlv
          post_tlv = tlv.tlvs.find { |t| t.type == Msf::Payload::MalleableC2::MET::TLV_TYPE_C2_POST }
          uri_tlvs = post_tlv.tlvs.select { |t| t.type == Msf::Payload::MalleableC2::MET::TLV_TYPE_C2_URI }
          uri_tlvs.each do |uri_tlv|
            expect(uri_tlv.value).not_to include('id='),
              "POST URI '#{uri_tlv.value}' contains 'id=' — single-arg id parameter directives " \
              "must not be emitted as static query string parameters"
          end
        end
      end
    end
  end
end
