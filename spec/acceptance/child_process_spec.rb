require 'acceptance_spec_helper'

RSpec.describe Acceptance::ChildProcess do
  context 'when a process is opened successfully' do
    let(:stdin_pipes) { ::IO.pipe }
    let(:stdin_reader) { stdin_pipes[0] }
    let(:stdin_writer) { stdin_pipes[1] }
    let(:stdout_and_stderr_pipes) { ::IO.pipe }
    let(:stdout_and_stderr_pipes_reader) { stdout_and_stderr_pipes[0] }
    let(:stdout_and_stderr_pipes_writer) { stdout_and_stderr_pipes[1] }
    let(:wait_thread) { double(:wait_thread, alive?: true, pid: nil) }

    subject(:mock_process) do
      clazz = Class.new(described_class) do
        attr_reader :mock_stdin_reader
        attr_reader :mock_stdout_and_stderr_writer

        def run(stdin, stdout_and_stderr, wait_thread)
          self.stdin = stdin
          self.stdout_and_stderr = stdout_and_stderr
          self.stdin.sync = true
          self.stdout_and_stderr.sync = true
          self.wait_thread = wait_thread
        end
      end
      clazz.new
    end

    def mock_write(data)
      stdout_and_stderr_pipes_writer.write(data)
    end

    before(:each) do
      mock_process.run(stdin_writer, stdout_and_stderr_pipes_reader, wait_thread)
    end

    after(:each) do
      subject.close
    end

    describe '#readline' do
      context 'when there is exactly one line available' do
        it 'reads one line' do
          mock_write("hello world\n")
          expect(subject.readline).to eq("hello world\n")
        end
      end

      context 'when there are multiple lines available' do
        it 'reads one line' do
          mock_write("hello world\nfoo bar\n")
          expect(subject.readline).to eq("hello world\n")
        end

        it 'reads multiple lines' do
          mock_write("hello world\nfoo bar\n")
          expect(subject.readline).to eq("hello world\n")
          expect(subject.readline).to eq("foo bar\n")
        end
      end
    end

    describe '#recv_available' do
      context 'when there is exactly one line available' do
        it 'reads one line' do
          mock_write("hello world\n")
          expect(subject.recv_available).to eq("hello world\n")
        end
      end

      context 'when there are multiple lines available' do
        it 'reads one line' do
          mock_write("hello world\nfoo bar\n")
          expect(subject.recv_available).to eq("hello world\nfoo bar\n")
        end
      end
    end

    describe '#recvuntil' do
      context 'when there are multiple lines of data available' do
        it 'reads one line' do
          mock_write <<~EOF
           motd
           login:
          EOF
          expect(subject.recvuntil("login:")).to eq("motd\nlogin:")
        end
      end
    end

    describe '#sendline' do
      it 'writes the available data' do
        subject.sendline("hello world")

        expect(stdin_reader.read_nonblock(1024)).to eq("hello world\n")
      end
    end

    describe '#alive?' do
      it 'returns the wait thread status' do
        expect(subject.alive?).to eq(wait_thread.alive?)
      end
    end
  end
end
