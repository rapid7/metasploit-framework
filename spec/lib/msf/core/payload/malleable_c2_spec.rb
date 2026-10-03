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

      context 'with a tricky escaped string' do
        # The string-token rule was tightened so its two alternatives are
        # disjoint (a backslash can only begin an escape). These lock in that
        # it still consumes escapes exactly as before -- the behaviour most at
        # risk from that change. Byte arrays are used so the expected value is
        # unambiguous regardless of Ruby string-literal escaping.
        it 'keeps an escaped quote inside the value' do
          profile = parse_profile('set useragent "a\\"b";')
          expect(profile.useragent.bytes).to eq([97, 34, 98]) # a " b
        end

        it 'handles a value ending in an escaped backslash' do
          profile = parse_profile('set useragent "c\\\\";')
          expect(profile.useragent.bytes).to eq([99, 92]) # c \
        end

        it 'decodes hex and control escapes' do
          profile = parse_profile('set useragent "x\\x41\\ty";')
          expect(profile.useragent.bytes).to eq([120, 65, 9, 121]) # x A \t y
        end
      end

      context 'with an unterminated string' do
        it 'is rejected rather than accepted as a token' do
          # A quote with no closing quote must not tokenize; the lexer reports
          # an unexpected token. (With the tightened rule this also rejects in
          # linear time, but that property is exercised offline, not here --
          # the suite runs with a global Regexp.timeout that would mask it.)
          expect do
            parse_profile('set useragent "' + ('\\' * 64))
          end.to raise_error(RuntimeError, /Unexpected token/)
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
