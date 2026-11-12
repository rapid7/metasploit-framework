require 'spec_helper'

RSpec.describe Msf::Post::File do
  describe '#read_file' do
    subject do
      described_mixin = described_class
      klass = Class.new do
        include described_mixin
        attr_accessor :session
      end
      klass.allocate
    end

    let(:session) { double('session', type: 'shell', platform: 'linux') }
    let(:file_name) { '/tmp/test_file' }
    let(:file_content) { 'file contents' }

    before do
      subject.session = session
    end

    it 'uses a 60-second timeout for Unix shell file reads' do
      expect(described_class::UNIX_FILE_READ_TIMEOUT).to eq(60)
    end

    it 'uses an extended timeout when reading a Unix file with cat' do
      allow(subject).to receive(:readable?).with(file_name).and_return(true)
      allow(subject).to receive(:command_exists?).with('cat').and_return(true)

      expect(session).to receive(:shell_command_token)
        .with("cat \"#{file_name}\"", described_class::UNIX_FILE_READ_TIMEOUT)
        .and_return(file_content)

      expect(subject.read_file(file_name)).to eq(file_content)
    end

    it 'uses the default timeout when reading a Windows file' do
      allow(session).to receive(:platform).and_return('windows')

      expect(session).to receive(:shell_command_token)
        .with("type \"#{file_name}\"")
        .and_return(file_content)

      expect(subject.read_file(file_name)).to eq(file_content)
    end

    it 'uses an extended timeout when reading a Unix file without cat' do
      allow(subject).to receive(:readable?).with(file_name).and_return(true)
      allow(subject).to receive(:command_exists?).with('cat').and_return(false)

      expect(session).to receive(:shell_command_token)
        .with("while read line; do echo $line; done <#{file_name}", described_class::UNIX_FILE_READ_TIMEOUT)
        .and_return(file_content)

      expect(subject.read_file(file_name)).to eq(file_content)
    end
  end
end
