# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/ftp/server'

RSpec.describe Rex::Proto::Ftp::Server do
  subject(:server) { described_class.new(0, '127.0.0.1') }

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Read one CRLF-terminated line from a raw TCP socket.
  def ftp_readline(sock)
    sock.gets("\r\n").to_s
  end

  # Send a command and return the server's one-line response.
  def ftp_cmd(sock, command)
    sock.write("#{command}\r\n")
    ftp_readline(sock)
  end

  # Open a control connection to the running server and consume the banner.
  # Yields the socket; closes it on block exit.
  def with_connection
    port = server.listener.getsockname[2]
    sock = TCPSocket.new('127.0.0.1', port)
    ftp_readline(sock) # consume 220 banner
    yield sock
  ensure
    sock&.close
  end

  # Authenticate on an already-connected socket.
  def authenticate(sock)
    ftp_cmd(sock, 'USER anonymous')
    ftp_cmd(sock, 'PASS test@test.com')
  end

  # Send PASV and return an open data socket.
  def pasv_data_socket(sock)
    resp = ftp_cmd(sock, 'PASV')
    parts = resp.match(/\(([^)]+)\)/)[1].split(',')
    port  = parts[4].to_i * 256 + parts[5].to_i
    TCPSocket.new('127.0.0.1', port)
  end

  # ---------------------------------------------------------------------------
  # Class methods
  # ---------------------------------------------------------------------------

  describe '.hardcore_alias' do
    it 'returns host-port' do
      expect(described_class.hardcore_alias(21, '10.0.0.1')).to eq('10.0.0.1-21')
    end

    it 'ignores extra arguments' do
      expect(described_class.hardcore_alias(2121, '192.168.1.1', 'ignored')).to eq('192.168.1.1-2121')
    end
  end

  # ---------------------------------------------------------------------------
  # Instance attributes
  # ---------------------------------------------------------------------------

  describe '#alias' do
    it 'returns "FTP Server" by default' do
      expect(server.alias).to eq('FTP Server')
    end

    it 'returns @alias when set' do
      server.instance_variable_set(:@alias, 'My FTP')
      expect(server.alias).to eq('My FTP')
    end
  end

  describe '#initialize' do
    it 'stores the port' do
      s = described_class.new(2121, '0.0.0.0')
      expect(s.listen_port).to eq(2121)
    end

    it 'stores the host' do
      s = described_class.new(21, '192.168.1.5')
      expect(s.listen_host).to eq('192.168.1.5')
    end

    it 'defaults port to 21' do
      s = described_class.new
      expect(s.listen_port).to eq(21)
    end

    it 'defaults host to 0.0.0.0' do
      s = described_class.new
      expect(s.listen_host).to eq('0.0.0.0')
    end

    it 'initializes files to an empty hash' do
      expect(server.files).to eq({})
    end

    it 'initializes serve_once to an empty hash' do
      expect(server.serve_once).to eq({})
    end

    it 'initializes shutting_down to false' do
      expect(server.shutting_down).to be(false)
    end

    it 'initializes listener to nil' do
      expect(server.listener).to be_nil
    end

    it 'initializes monitor_thread to nil' do
      expect(server.monitor_thread).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # File management
  # ---------------------------------------------------------------------------

  describe '#register_file' do
    it 'stores the file data' do
      server.register_file('payload', 'data')
      expect(server.files['payload']).to eq('data')
    end

    it 'defaults serve_once to true' do
      server.register_file('payload', 'data')
      expect(server.serve_once['payload']).to be(true)
    end

    it 'accepts serve_once: false' do
      server.register_file('payload', 'data', serve_once: false)
      expect(server.serve_once['payload']).to be(false)
    end

    it 'accepts serve_once: true explicitly' do
      server.register_file('payload', 'data', serve_once: true)
      expect(server.serve_once['payload']).to be(true)
    end

    it 'can register multiple files' do
      server.register_file('a', 'aaa')
      server.register_file('b', 'bbb')
      expect(server.files.keys).to contain_exactly('a', 'b')
    end

    it 'overwrites an existing registration' do
      server.register_file('payload', 'old')
      server.register_file('payload', 'new')
      expect(server.files['payload']).to eq('new')
    end
  end

  describe '#deregister_file' do
    before { server.register_file('payload', 'data') }

    it 'removes the file' do
      server.deregister_file('payload')
      expect(server.files).not_to have_key('payload')
    end

    it 'removes the serve_once entry' do
      server.deregister_file('payload')
      expect(server.serve_once).not_to have_key('payload')
    end

    it 'is a no-op for an unknown filename' do
      expect { server.deregister_file('nonexistent') }.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # Lifecycle
  # ---------------------------------------------------------------------------

  describe '#start and #stop' do
    after { server.stop rescue nil }

    it 'sets the listener after start' do
      server.start
      expect(server.listener).not_to be_nil
    end

    it 'spawns a monitor thread after start' do
      server.start
      expect(server.monitor_thread).to be_a(Thread)
    end

    it 'sets shutting_down on stop' do
      server.start
      server.stop
      expect(server.shutting_down).to be(true)
    end

    it 'can be started and stopped without error' do
      expect { server.start; server.stop }.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # FTP protocol behaviour
  # ---------------------------------------------------------------------------

  describe 'FTP protocol' do
    before(:each) { server.start }
    after(:each)  { server.stop rescue nil }

    describe 'connection banner' do
      it 'sends a 220 greeting on connect' do
        port = server.listener.getsockname[2]
        sock = TCPSocket.new('127.0.0.1', port)
        banner = ftp_readline(sock)
        expect(banner).to start_with('220 ')
      ensure
        sock&.close
      end
    end

    describe 'USER' do
      it 'responds 331 requesting password' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'USER anonymous')
          expect(resp).to start_with('331 ')
        end
      end
    end

    describe 'PASS' do
      it 'responds 230 on any password' do
        with_connection do |sock|
          ftp_cmd(sock, 'USER anonymous')
          resp = ftp_cmd(sock, 'PASS anything')
          expect(resp).to start_with('230 ')
        end
      end
    end

    describe 'QUIT' do
      it 'responds 221' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'QUIT')
          expect(resp).to start_with('221 ')
        end
      end
    end

    describe 'SYST' do
      it 'responds 215 UNIX' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'SYST')
          expect(resp).to start_with('215 UNIX')
        end
      end
    end

    describe 'TYPE' do
      it 'responds 200 echoing the type argument' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'TYPE I')
          expect(resp).to match(/^200 .*I/)
        end
      end
    end

    describe 'MODE' do
      it 'responds 200 echoing the mode argument' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'MODE S')
          expect(resp).to match(/^200 .*S/)
        end
      end
    end

    describe 'NOOP' do
      it 'responds 200' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'NOOP')
          expect(resp).to start_with('200 ')
        end
      end
    end

    describe 'FEAT' do
      it 'responds 211 and advertises PASV' do
        with_connection do |sock|
          sock.write("FEAT\r\n")
          lines = []
          loop do
            line = ftp_readline(sock)
            lines << line
            break if line.start_with?('211 ')
          end
          full = lines.join
          expect(full).to include('PASV')
        end
      end
    end

    describe 'PWD / XPWD' do
      it 'responds 257 with the current directory in quotes' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'PWD')
          expect(resp).to match(/^257 "\/"\s/)
        end
      end

      it 'XPWD behaves the same as PWD' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'XPWD')
          expect(resp).to start_with('257 ')
        end
      end
    end

    describe 'CWD' do
      it 'responds 250 and updates cwd for an absolute path' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'CWD /pub')
          expect(resp).to start_with('250 ')
          pwd = ftp_cmd(sock, 'PWD')
          expect(pwd).to include('"/pub"')
        end
      end

      it 'appends a relative path to the current directory' do
        with_connection do |sock|
          ftp_cmd(sock, 'CWD /pub')
          ftp_cmd(sock, 'CWD files')
          pwd = ftp_cmd(sock, 'PWD')
          expect(pwd).to include('"/pub/files"')
        end
      end
    end

    describe 'CDUP' do
      it 'responds 250 and moves up one directory' do
        with_connection do |sock|
          ftp_cmd(sock, 'CWD /pub/files')
          ftp_cmd(sock, 'CDUP')
          pwd = ftp_cmd(sock, 'PWD')
          expect(pwd).to include('"/pub"')
        end
      end
    end

    describe 'PASV' do
      it 'responds 227 with host and port' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'PASV')
          expect(resp).to start_with('227 ')
          expect(resp).to match(/\(\d+,\d+,\d+,\d+,\d+,\d+\)/)
        end
      end

      it 'encodes a non-zero port in the 227 response' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'PASV')
          parts = resp.match(/\(([^)]+)\)/)[1].split(',')
          port = parts[4].to_i * 256 + parts[5].to_i
          expect(port).to be > 0
        end
      end
    end

    describe 'PORT' do
      it 'responds 200 for a valid PORT argument' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'PORT 127,0,0,1,4,1')
          expect(resp).to start_with('200 ')
        end
      end

      it 'responds 500 for a malformed PORT argument' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'PORT invalid')
          expect(resp).to start_with('500 ')
        end
      end
    end

    describe 'SIZE' do
      before { server.register_file('payload.bin', 'A' * 100) }

      it 'responds 213 with the file size for a known file' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'SIZE payload.bin')
          expect(resp).to match(/^213 100\r\n/)
        end
      end

      it 'responds 550 for an unknown file' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'SIZE missing.bin')
          expect(resp).to start_with('550 ')
        end
      end
    end

    describe 'write commands' do
      %w[STOR MKD RMD DELE RNFR RNTO APPE STOU].each do |cmd|
        it "responds 550 Permission denied for #{cmd}" do
          with_connection do |sock|
            resp = ftp_cmd(sock, "#{cmd} anything")
            expect(resp).to start_with('550 ')
          end
        end
      end
    end

    describe 'unknown commands' do
      it 'responds 502 for unrecognised commands' do
        with_connection do |sock|
          resp = ftp_cmd(sock, 'XYZZY')
          expect(resp).to start_with('502 ')
        end
      end
    end

    describe 'LIST' do
      before { server.register_file('payload.bin', 'data') }

      it 'responds 530 when not authenticated' do
        with_connection do |sock|
          ftp_cmd(sock, 'PASV')
          resp = ftp_cmd(sock, 'LIST')
          expect(resp).to start_with('530 ')
        end
      end

      it 'sends a directory listing over the data connection' do
        with_connection do |sock|
          authenticate(sock)
          data_sock = pasv_data_socket(sock)
          ftp_cmd(sock, 'LIST')          # 150
          listing = data_sock.read
          data_sock.close
          ftp_readline(sock)             # 226

          expect(listing).to include('payload.bin')
        end
      end

      it 'includes the file size in the listing' do
        with_connection do |sock|
          authenticate(sock)
          data_sock = pasv_data_socket(sock)
          ftp_cmd(sock, 'LIST')
          listing = data_sock.read
          data_sock.close
          ftp_readline(sock)

          expect(listing).to include('4') # 'data'.bytesize
        end
      end
    end

    describe 'RETR' do
      let(:file_content) { 'BINARY_PAYLOAD_DATA' }

      before { server.register_file('payload.bin', file_content) }

      it 'responds 530 when not authenticated' do
        with_connection do |sock|
          ftp_cmd(sock, 'PASV')
          resp = ftp_cmd(sock, 'RETR payload.bin')
          expect(resp).to start_with('530 ')
        end
      end

      it 'responds 550 for an unknown file' do
        with_connection do |sock|
          authenticate(sock)
          data_sock = pasv_data_socket(sock)
          resp = ftp_cmd(sock, 'RETR missing.bin')
          data_sock.close
          expect(resp).to start_with('550 ')
        end
      end

      it 'transfers the correct file content' do
        with_connection do |sock|
          authenticate(sock)
          data_sock = pasv_data_socket(sock)
          ftp_cmd(sock, 'RETR payload.bin')  # 150
          received = data_sock.read
          data_sock.close
          ftp_readline(sock)                 # 226

          expect(received).to eq(file_content)
        end
      end

      it 'sends 150 then 226 around the transfer' do
        with_connection do |sock|
          authenticate(sock)
          data_sock = pasv_data_socket(sock)
          opening = ftp_cmd(sock, 'RETR payload.bin')
          data_sock.read
          data_sock.close
          complete = ftp_readline(sock)

          expect(opening).to start_with('150 ')
          expect(complete).to start_with('226 ')
        end
      end

      context 'with serve_once: true (default)' do
        it 'removes the file after retrieval' do
          with_connection do |sock|
            authenticate(sock)
            data_sock = pasv_data_socket(sock)
            ftp_cmd(sock, 'RETR payload.bin')
            data_sock.read
            data_sock.close
            ftp_readline(sock)

            expect(server.files).not_to have_key('payload.bin')
          end
        end

        it 'responds 550 on a second RETR attempt' do
          with_connection do |sock|
            authenticate(sock)

            # First retrieval
            data_sock = pasv_data_socket(sock)
            ftp_cmd(sock, 'RETR payload.bin')
            data_sock.read
            data_sock.close
            ftp_readline(sock)

            # Second attempt
            ftp_cmd(sock, 'PASV')
            resp = ftp_cmd(sock, 'RETR payload.bin')
            expect(resp).to start_with('550 ')
          end
        end
      end

      context 'with serve_once: false' do
        before { server.register_file('payload.bin', file_content, serve_once: false) }

        it 'keeps the file after retrieval' do
          with_connection do |sock|
            authenticate(sock)
            data_sock = pasv_data_socket(sock)
            ftp_cmd(sock, 'RETR payload.bin')
            data_sock.read
            data_sock.close
            ftp_readline(sock)

            expect(server.files).to have_key('payload.bin')
          end
        end

        it 'serves the file on a second RETR' do
          with_connection do |sock|
            authenticate(sock)

            2.times do
              data_sock = pasv_data_socket(sock)
              ftp_cmd(sock, 'RETR payload.bin')
              received = data_sock.read
              data_sock.close
              ftp_readline(sock)
              expect(received).to eq(file_content)
            end
          end
        end
      end
    end
  end
end
