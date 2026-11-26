require 'tempfile'
require 'tmpdir'

require 'rex/parser/ini'

RSpec.describe Rex::Parser::Ini do
  let(:ini_contents) { <<EOF
# global comment
global setting = blah
[foo]
a = b
[bar]
b = c

[baf]
c = d
EOF
  }

  let(:ini) { described_class.from_s(ini_contents) }

  context "#each_group" do
    it "enumerates the groups" do
      groups = []
      ini.each_group { |group| groups << group }
      expect(groups).to eq(%w(foo bar baf))
    end
  end

  context "#each_key" do
    it "enumerates the groups" do
      groups = []
      ini.each_key.map { |group| groups << group }
      expect(groups).to eq(%w(foo bar baf))
    end
  end

  describe '#to_file' do
    it 'writes the serialized groups and returns nil' do
      Dir.mktmpdir do |directory|
        path = File.join(directory, 'config.ini')
        File.write(path, "[old]\nvalue=obsolete\n")

        expect(ini.to_file(path)).to be_nil
        expect(File.read(path)).to eq(ini.to_s)
      end
    end

    it 'closes the file and propagates the write error', :aggregate_failures do
      Tempfile.create('config') do |file|
        error = Errno::ENOSPC.new
        allow(File).to receive(:new).and_call_original
        allow(File).to receive(:new).with(file.path, 'w').and_return(file)
        allow(file).to receive(:write).with(ini.to_s).and_raise(error)

        expect { ini.to_file(file.path) }.to raise_error(Errno::ENOSPC) do |raised_error|
          expect(raised_error).to equal(error)
        end
        expect(file).to be_closed
      end
    end

    it 'propagates an error opening the destination' do
      Dir.mktmpdir do |directory|
        path = File.join(directory, 'missing', 'config.ini')

        expect { ini.to_file(path) }.to raise_error(Errno::ENOENT)
      end
    end
  end
end
