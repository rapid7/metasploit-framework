require 'spec_helper'

RSpec.describe Msf::Post::Linux::Priv do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Linux::Priv)
    mod
  end

  before do
    allow(subject).to receive(:command_exists?).and_return(true)
    allow(subject).to receive(:cmd_exec).and_return('')
  end

  describe '#is_root?' do
    context 'when the id command exists' do
      it 'returns true if the user ID is 0' do
        allow(subject).to receive(:cmd_exec).with('id -u').and_return('0')
        expect(subject.is_root?).to be true
      end

      it 'returns false if the user ID is not 0' do
        allow(subject).to receive(:cmd_exec).with('id -u').and_return('1000')
        expect(subject.is_root?).to be false
      end

      it 'raises an error if the user ID cannot be determined' do
        allow(subject).to receive(:cmd_exec).with('id -u').and_return('abc')
        expect { subject.is_root? }.to raise_error(RuntimeError, 'Could not determine UID: "abc"')
      end
    end
  end

  describe '#cp_cmd' do
    it 'copies the content of one file to another' do
      origin_file = '/path/to/origin'
      final_file = '/path/to/destination'
      file_content = 'file content'

      allow(subject).to receive(:read_file).with(origin_file).and_return(file_content)
      expect(subject).to receive(:cmd_exec).with("echo '#{file_content}' > '#{final_file}'")

      subject.cp_cmd(origin_file, final_file)
    end
  end

  describe '#binary_of_pid' do
    it 'retrieves the binary name of a process given its PID' do
      pid = 1234
      cmdline_content = '/usr/bin/bash'
      comm_content = 'bash'

      allow(subject).to receive(:read_file).with("/proc/#{pid}/cmdline").and_return(cmdline_content)
      expect(subject.binary_of_pid(pid)).to eq('/usr/bin/bash')

      allow(subject).to receive(:read_file).with("/proc/#{pid}/cmdline").and_return('')
      allow(subject).to receive(:read_file).with("/proc/#{pid}/comm").and_return(comm_content)
      expect(subject.binary_of_pid(pid)).to eq('bash')
    end
  end

  describe '#seq' do
    it 'generates a sequence of numbers from first to last with a given increment' do
      expect(subject.seq(1, 2, 10)).to eq([1, 3, 5, 7, 9])
      expect(subject.seq(0, 5, 20)).to eq([0, 5, 10, 15, 20])
    end
  end

  describe '#wc_cmd' do
    it 'returns the number of lines, words, and characters in a file' do
      file = '/path/to/file'
      allow(subject).to receive(:nlines_file).with(file).and_return(10)
      allow(subject).to receive(:nwords_file).with(file).and_return(20)
      allow(subject).to receive(:nchars_file).with(file).and_return(100)

      expect(subject.wc_cmd(file)).to eq([10, 20, 100, file])
    end
  end

  describe '#nchars_file' do
    it 'returns the number of characters in a file' do
      file = '/path/to/file'
      file_content = "Hello\nWorld"
      allow(subject).to receive(:read_file).with(file).and_return(file_content)

      # agrees with wc
      # $ echo -n "Hello\nWorld" | wc -m
      # 12
      expect(subject.nchars_file(file)).to eq(12)
    end
  end

  describe '#nwords_file' do
    it 'returns the number of words in a file' do
      file = '/path/to/file'
      file_content = "Hello World\nThis is a test"
      allow(subject).to receive(:read_file).with(file).and_return(file_content)

      expect(subject.nwords_file(file)).to eq(6)
    end
  end

  describe '#nlines_file' do
    it 'returns the number of lines in a file' do
      file = '/path/to/file'
      file_content = "Hello\nWorld\nThis is a test"
      allow(subject).to receive(:read_file).with(file).and_return(file_content)

      expect(subject.nlines_file(file)).to eq(3)
    end
  end

  describe '#head_cmd' do
    it 'returns the first n lines of a file' do
      file = '/path/to/file'
      file_content = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
      allow(subject).to receive(:read_file).with(file).and_return(file_content)

      expect(subject.head_cmd(file, 3)).to eq(['Line 1', 'Line 2', 'Line 3'])
    end
  end

  describe '#tail_cmd' do
    it 'returns the last n lines of a file' do
      file = '/path/to/file'
      file_content = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
      allow(subject).to receive(:read_file).with(file).and_return(file_content)

      expect(subject.tail_cmd(file, 3)).to eq(['Line 3', 'Line 4', 'Line 5'])
    end
  end

  describe '#grep_cmd' do
    it 'searches for a specific string in a file and returns the lines that contain the string' do
      file = '/path/to/file'
      file_content = "Hello World\nThis is a test\nHello again"
      allow(subject).to receive(:read_file).with(file).and_return(file_content)

      expect(subject.grep_cmd(file, 'Hello')).to eq(['Hello World', 'Hello again'])
    end
  end
end
