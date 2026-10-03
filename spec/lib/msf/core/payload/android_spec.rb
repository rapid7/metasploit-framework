require 'spec_helper'
require 'rex/zip'
require 'zip'

RSpec.describe Msf::Payload::Android do
  subject(:payload) { Class.new(Msf::Payload).include(described_class).new }

  describe '#generate_jar' do
    before do
      allow(payload).to receive(:generate_config) { config.dup }
      allow(payload).to receive(:sign_jar)
    end

    [false, true].each do |stageless|
      context "with #{stageless ? 'stageless' : 'staged'} configuration" do
        let(:original_dex) do
          if stageless
            MetasploitPayloads.read('android', 'meterpreter.dex')
          else
            MetasploitPayloads.read('android', 'apk', 'classes.dex')
          end
        end

        let(:marker) { "\xde\xad\xba\xad".b + "\x00" * 8191 }
        let(:expected_config) do
          if stageless
            (config.ljust(8000, "\x00") + 'com.metasploit.meterpreter.AndroidMeterpreter').ljust(8195, "\x00")
          else
            config.ljust(8195, "\x00")
          end
        end

        {
          'ordinary binary bytes' => "\x00\xff\x80config".b,
          'an incomplete named backreference' => "\x00\\k<\xff".b,
          'a numbered backreference' => "\x00\\1\xff".b,
          'a whole-match backreference' => "\x00\\&\xff".b
        }.each do |description, bytes|
          context "containing #{description}" do
            let(:config) { bytes }

            it 'preserves the configuration and surrounding DEX data' do
              jar = payload.generate_jar(stageless: stageless)
              dex = nil
              Zip::File.open_buffer(jar.pack) { |archive| dex = archive.read('classes.dex') }
              offset = original_dex.index(marker)
              expect(offset).not_to be_nil

              expected_dex = original_dex.dup
              expected_dex[offset, marker.bytesize] = expected_config
              expect(dex.bytesize).to eq(original_dex.bytesize)
              expect(dex.byteslice(0, 8)).to eq(original_dex.byteslice(0, 8))
              expect(dex.byteslice(32..)).to eq(expected_dex.byteslice(32..))
              expect(dex.byteslice(12, 20)).to eq(Digest::SHA1.digest(dex.byteslice(32..)))
              expect(dex.byteslice(8, 4).unpack1('V')).to eq(Zlib.adler32(dex.byteslice(12..)))
            end
          end
        end
      end
    end
  end
end
