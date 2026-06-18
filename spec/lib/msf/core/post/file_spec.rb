require 'spec_helper'
require 'rex/text'

RSpec.describe Msf::Post::File do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin
    end
    klass.allocate
  end

  describe '#mkdir' do
    let(:path) { '/tmp/test_dir' }

    subject do
      described_mixin = described_class
      klass = Class.new do
        include described_mixin
        attr_accessor :session
        def cmd_exec(_cmd); ''; end
        def vprint_status(_msg); end
        def register_dir_for_cleanup(_path); end
      end
      obj = klass.allocate
      obj.session = double('session', type: 'shell', platform: 'linux')
      obj
    end

    before(:each) do
      allow(subject).to receive(:register_dir_for_cleanup)
    end

    it 'registers the directory for cleanup by default' do
      subject.mkdir(path)
      expect(subject).to have_received(:register_dir_for_cleanup).with(path)
    end

    it 'does not register the directory for cleanup when cleanup is false' do
      subject.mkdir(path, cleanup: false)
      expect(subject).not_to have_received(:register_dir_for_cleanup)
    end
  end

  describe '#_can_echo?' do
    [
      # printable examples
      { input: '', expected: true },
      { input: 'hello world', expected: true },
      { input: "hello 'world'", expected: true },
      { input: "!@^&*()_+[]{}:|<>?,./;'\\[]1234567890-='", expected: true },

      # non-printable character examples, or breaking characters such as new line or quotes etc
      { input: "a\nb\nc", expected: false },
      { input: "\xff\x00", expected: false },
      { input: "\x00\x01\x02\x03\x04\x1f", expected: false },
      { input: "hello \"world\"", expected: false },
      { input: "🐂", expected: false },
      { input: "%APPDATA%", expected: false },
      { input: "$HOME", expected: false }
    ].each do |test|
      it "should return #{test[:expected]} for #{test[:input].inspect}" do
        expect(subject.send(:_can_echo?, test[:input])).to eql(test[:expected])
      end
    end
  end

  describe '#find_writable_directories' do
    subject do
      described_mixin = described_class
      klass = Class.new do
        include described_mixin
        attr_accessor :session
        def cmd_exec(*_args); ''; end
        def print_warning(_msg); end
        def print_error(_msg); end
        def elog(*_args); end
      end
      obj = klass.allocate
      obj.session = double('session', platform: 'linux')
      allow(obj.session).to receive(:escape_arg) { |arg| "'#{arg}'" }
      obj
    end

    context 'on Windows' do
      before(:each) do
        allow(subject.session).to receive(:platform).and_return('windows')
      end

      it 'raises an error' do
        expect { subject.find_writable_directories }.to raise_error(RuntimeError, /does not support Windows/)
      end
    end

    it 'raises an error for relative paths' do
      expect { subject.find_writable_directories(path: 'relative/path') }.to raise_error(ArgumentError, /absolute path/)
    end

    it 'raises an error for negative max_depth' do
      expect { subject.find_writable_directories(max_depth: -1) }.to raise_error(ArgumentError, /max_depth must not be negative/)
    end

    context 'on Unix' do

      it 'returns writable directories' do
        allow(subject).to receive(:cmd_exec).and_return("/tmp\n/var/tmp\n")
        expect(subject.find_writable_directories).to eq(['/tmp', '/var/tmp'])
      end

      it 'filters out non-absolute paths and error lines' do
        allow(subject).to receive(:cmd_exec).and_return("/tmp\nfind: permission denied\n/var/tmp\n")
        expect(subject.find_writable_directories).to eq(['/tmp', '/var/tmp'])
      end

      it 'returns an empty array when no directories are found' do
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.find_writable_directories).to eq([])
      end

      it 'passes the timeout to cmd_exec' do
        expect(subject).to receive(:cmd_exec).with("find '/' -maxdepth 2 -type d -writable 2>/dev/null", nil, 15).and_return("/tmp\n")
        subject.find_writable_directories
      end

      it 'passes a custom timeout to cmd_exec' do
        expect(subject).to receive(:cmd_exec).with("find '/' -maxdepth 2 -type d -writable 2>/dev/null", nil, 60).and_return("/tmp\n")
        subject.find_writable_directories(timeout: 60)
      end

      it 'uses default timeout when timeout is 0' do
        expect(subject).to receive(:cmd_exec).with("find '/' -maxdepth 2 -type d -writable 2>/dev/null", nil, 15).and_return("/tmp\n")
        subject.find_writable_directories(timeout: 0)
      end

      it 'warns when max_depth is greater than 2' do
        expect(subject).to receive(:print_warning).with(/Large max_depth/)
        allow(subject).to receive(:cmd_exec).and_return("/tmp\n")
        subject.find_writable_directories(max_depth: 5)
      end

      it 'does not warn when max_depth is 2 or less' do
        expect(subject).not_to receive(:print_warning)
        allow(subject).to receive(:cmd_exec).and_return("/tmp\n")
        subject.find_writable_directories(max_depth: 2)
      end

      it 'passes -maxdepth 0 to search only the base directory' do
        expect(subject).to receive(:cmd_exec).with("find '/' -maxdepth 0 -type d -writable 2>/dev/null", nil, 15).and_return("/\n")
        expect(subject.find_writable_directories(max_depth: 0)).to eq(['/'])
      end

      it 'uses custom path and max_depth' do
        allow(subject).to receive(:print_warning)
        expect(subject).to receive(:cmd_exec).with("find '/var' -maxdepth 3 -type d -writable 2>/dev/null", nil, 15).and_return("/var/tmp\n")
        expect(subject.find_writable_directories(path: '/var', max_depth: 3)).to eq(['/var/tmp'])
      end

      it 'returns nil on failure' do
        allow(subject).to receive(:cmd_exec).and_raise(RuntimeError, 'connection failed')
        allow(subject).to receive(:print_error)
        allow(subject).to receive(:elog)
        expect(subject.find_writable_directories).to be_nil
      end
    end
  end

  describe '#writable?' do
    subject do
      described_mixin = described_class
      klass = Class.new do
        include described_mixin
        attr_accessor :session
        def cmd_exec(_cmd); ''; end
      end
      obj = klass.allocate
      obj.session = double('session')
      obj
    end

    before(:each) do
      allow(Rex::Text).to receive(:rand_text_alpha_upper).and_return('TESTTOKEN')
    end

    context 'on a Windows shell session' do
      before(:each) do
        allow(subject.session).to receive(:type).and_return('shell')
        allow(subject.session).to receive(:platform).and_return('windows')
        allow(subject).to receive(:directory?).and_return(false)
      end

      it 'returns true when the file is writable' do
        allow(subject).to receive(:file?).with('C:\\writable.txt').and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('TESTTOKEN')
        expect(subject.writable?('C:\\writable.txt')).to be true
      end

      it 'returns false when the file is not writable' do
        allow(subject).to receive(:file?).with('C:\\locked.txt').and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.writable?('C:\\locked.txt')).to be false
      end

      it 'returns true when the directory is writable' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(true)
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('RANDFILE')
        allow(subject).to receive(:cmd_exec)
          .with('type nul >> "C:\\somedir\\RANDFILE.tmp" 2>nul && del "C:\\somedir\\RANDFILE.tmp" && echo TESTTOKEN')
          .and_return('TESTTOKEN')
        expect(subject.writable?('C:\\somedir')).to be true
      end

      it 'returns false when the directory is not writable' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(true)
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('RANDFILE')
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.writable?('C:\\somedir')).to be false
      end

      it 'returns false when the path does not exist' do
        allow(subject).to receive(:directory?).with('C:\\missing').and_return(false)
        allow(subject).to receive(:file?).with('C:\\missing').and_return(false)
        expect(subject.writable?('C:\\missing')).to be false
      end

      it 'issues the correct cmd.exe command' do
        allow(subject).to receive(:file?).with('C:\\test.txt').and_return(true)
        expect(subject).to receive(:cmd_exec)
          .with('type nul >> "C:\\test.txt" 2>nul && echo TESTTOKEN')
          .and_return('')
        subject.writable?('C:\\test.txt')
      end
    end

    context 'on a Windows meterpreter session' do
      let(:mock_fs)             { double('fs') }
      let(:mock_fs_file)        { double('fs_file') }
      let(:mock_fd)             { double('fd') }
      let(:request_error_class) { Class.new(StandardError) }

      before(:each) do
        stub_const('Rex::Post::Meterpreter::RequestError', request_error_class)
        allow(subject.session).to receive(:type).and_return('meterpreter')
        allow(subject.session).to receive(:platform).and_return('windows')
        allow(subject.session).to receive(:fs).and_return(mock_fs)
        allow(mock_fs).to receive(:file).and_return(mock_fs_file)
        allow(mock_fd).to receive(:close)
        allow(subject).to receive(:directory?).and_return(false)
      end

      it 'returns true when the file is writable' do
        allow(subject).to receive(:file?).with('C:\\writable.txt').and_return(true)
        allow(mock_fs_file).to receive(:new).and_return(mock_fd)
        expect(subject.writable?('C:\\writable.txt')).to be true
      end

      it 'returns false when opening the file raises a RequestError' do
        allow(subject).to receive(:file?).with('C:\\locked.txt').and_return(true)
        allow(mock_fs_file).to receive(:new).and_raise(request_error_class)
        expect(subject.writable?('C:\\locked.txt')).to be false
      end

      it 'opens the file with write mode' do
        allow(subject).to receive(:file?).with('C:\\test.txt').and_return(true)
        expect(mock_fs_file).to receive(:new).with('C:\\test.txt', 'wb').and_return(mock_fd)
        subject.writable?('C:\\test.txt')
      end

      it 'returns false for a non-file path' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(false)
        allow(subject).to receive(:file?).with('C:\\somedir').and_return(false)
        expect(mock_fs_file).not_to receive(:new)
        expect(subject.writable?('C:\\somedir')).to be false
      end

      it 'returns true when the directory is writable' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(true)
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('RANDFILE')
        allow(mock_fs_file).to receive(:new).with('C:\\somedir\\RANDFILE.tmp', 'wb').and_return(mock_fd)
        allow(mock_fs_file).to receive(:rm).with('C:\\somedir\\RANDFILE.tmp')
        expect(subject.writable?('C:\\somedir')).to be true
      end

      it 'returns false when the directory is not writable' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(true)
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('RANDFILE')
        allow(mock_fs_file).to receive(:new).with('C:\\somedir\\RANDFILE.tmp', 'wb').and_raise(request_error_class)
        expect(subject.writable?('C:\\somedir')).to be false
      end
    end

    context 'on a Windows PowerShell session' do
      before(:each) do
        allow(subject.session).to receive(:type).and_return('powershell')
        allow(subject.session).to receive(:platform).and_return('windows')
        allow(subject).to receive(:directory?).and_return(false)
      end

      it 'returns true when the file is writable' do
        allow(subject).to receive(:file?).with('C:\\writable.txt').and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('TESTTOKEN')
        expect(subject.writable?('C:\\writable.txt')).to be true
      end

      it 'returns false for a non-file path' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(false)
        allow(subject).to receive(:file?).with('C:\\somedir').and_return(false)
        expect(subject.writable?('C:\\somedir')).to be false
      end

      it 'returns true when the directory is writable' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(true)
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('RANDFILE')
        allow(subject).to receive(:cmd_exec)
          .with("$f=[System.IO.File]::Create('C:\\somedir\\RANDFILE.tmp');if($?){$f.Close();[System.IO.File]::Delete('C:\\somedir\\RANDFILE.tmp');echo TESTTOKEN}")
          .and_return('TESTTOKEN')
        expect(subject.writable?('C:\\somedir')).to be true
      end

      it 'returns false when the directory is not writable' do
        allow(subject).to receive(:directory?).with('C:\\somedir').and_return(true)
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('RANDFILE')
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.writable?('C:\\somedir')).to be false
      end
    end

    context 'on a Unix shell session' do
      before(:each) do
        allow(subject.session).to receive(:type).and_return('shell')
        allow(subject.session).to receive(:platform).and_return('linux')
      end

      it 'returns true when test -w succeeds' do
        allow(subject).to receive(:cmd_exec).and_return('true')
        expect(subject.writable?('/tmp/file')).to be true
      end

      it 'returns false when test -w fails' do
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.writable?('/etc/shadow')).to be false
      end
    end
  end
end
