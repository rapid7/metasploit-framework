# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

RSpec.describe Msf::Payload::MalleableC2 do
  let(:fixture_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures', 'malleable_c2') }

  describe Msf::Payload::MalleableC2::Parser do
    subject(:parser) { Msf::Payload::MalleableC2::Parser.new }

    def parse_profile(contents)
      Tempfile.create(['malleable-c2', '.profile']) do |file|
        file.write(contents)
        file.close

        parser.parse(file.path)
      end
    end

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
          expect do
            parser.parse('/nonexistent/path.profile')
          end.to raise_error(Errno::ENOENT)
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

    describe Msf::Payload::MalleableC2::ParsedSection do
      it 'returns a set value through method_missing when no matching directives exist' do
        profile = parse_profile(%q{
          http-get {
            client {
              set useragent "ScopedAgent/1.0";

              metadata {
                parameter "id";
              }
            }
          }
        })

        expect(profile.http_get.client.useragent).to eq('ScopedAgent/1.0')
      end
    end
  end
end
