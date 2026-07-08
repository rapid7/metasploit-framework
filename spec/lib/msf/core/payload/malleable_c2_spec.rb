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
  end
end
