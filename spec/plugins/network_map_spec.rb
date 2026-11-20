require 'spec_helper'
require Metasploit::Framework.root.join('plugins/network_map.rb').to_path
require 'net/http'
require 'base64'
require 'socket'
require 'timeout'

# Security behavior of the live network_map web server, per the OWASP HTML5
# Security Cheat Sheet (clickjacking, referrer policy, MIME sniffing, web
# storage, postMessage, tabnabbing, CORS) plus the password gate: nothing
# at all is served without the operator's password.
# https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
RSpec.describe Msf::Plugin::NetworkMapLive::LiveServer do
  subject(:server) do
    db = double('db', active: false)
    fw = double('framework', db: db, jobs: {})
    plug = double('plugin',
                  console_snapshot: { last_command: nil, tail: [] },
                  console_activity_version: 0,
                  reset_console_snapshot: nil,
                  tap_warning: nil,
                  tap_status: nil)
    described_class.new(fw, plug)
  end

  let(:password) { 'amber_river_owl' }

  before { server.start(host: '127.0.0.1', port: 0, interval: 3600, password: password) }
  after { server.stop }

  def http_get(path, auth: nil, host_header: nil)
    Net::HTTP.start('127.0.0.1', server.port) do |http|
      req = Net::HTTP::Get.new(path)
      req['Authorization'] = "Basic #{Base64.strict_encode64("user:#{auth}")}" if auth
      req['Host'] = host_header if host_header
      http.request(req)
    end
  end

  def ws_handshake(auth: nil, origin: nil)
    sock = TCPSocket.new('127.0.0.1', server.port)
    req = +"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:#{server.port}\r\n" \
           "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" \
           "Sec-WebSocket-Version: 13\r\n"
    req << "Authorization: Basic #{Base64.strict_encode64("user:#{auth}")}\r\n" if auth
    req << "Origin: #{origin}\r\n" if origin
    req << "\r\n"
    sock.write(req)
    line = sock.gets
    sock.close
    line.to_s
  end

  # Completes a websocket handshake and leaves the socket open for frame I/O.
  def ws_connect(auth: nil, origin: nil)
    sock = TCPSocket.new('127.0.0.1', server.port)
    req = +"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:#{server.port}\r\n" \
           "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" \
           "Sec-WebSocket-Version: 13\r\n"
    req << "Authorization: Basic #{Base64.strict_encode64("user:#{auth}")}\r\n" if auth
    req << "Origin: #{origin}\r\n" if origin
    req << "\r\n"
    sock.write(req)
    status = sock.gets
    raise "websocket handshake failed: #{status.inspect}" unless status.to_s.start_with?('HTTP/1.1 101')

    loop do
      line = sock.gets
      break if line.nil? || line == "\r\n"
    end
    sock
  end

  # Reads unmasked server frames until a ping (0x9) arrives, skipping text
  # frames (the initial snapshot). Returns true on ping, false on EOF.
  def ws_read_until_ping(sock)
    loop do
      head = sock.read(2)
      return false if head.nil? || head.bytesize < 2

      opcode = head.getbyte(0) & 0x0f
      len = head.getbyte(1) & 0x7f
      if len == 126
        ext = sock.read(2)
        return false if ext.nil? || ext.bytesize < 2

        len = ext.unpack1('n')
      elsif len == 127
        ext = sock.read(8)
        return false if ext.nil? || ext.bytesize < 8

        len = ext.unpack1('Q>')
      end
      return true if opcode == 0x9

      sock.read(len) unless len.zero?
    end
  end

  describe 'password gate' do
    it 'denies every endpoint without credentials' do
      %w[/ /index.html /d3.js /graph.json /health /ws /definitely-not-here].each do |path|
        res = http_get(path)
        aggregate_failures path do
          expect(res.code).to eq('401')
          expect(res['WWW-Authenticate']).to start_with('Basic realm=')
          expect(res.body).to eq("401 Unauthorized\n")
        end
      end
    end

    it 'serves the page and data with correct credentials' do
      page = http_get('/', auth: password)
      expect(page.code).to eq('200')
      expect(page.body).to include('MSF Network Graph')
      expect(http_get('/graph.json', auth: password).content_type).to eq('application/json')
      expect(http_get('/health', auth: password).body).to eq("ok\n")
    end

    it 'denies a wrong password' do
      expect(http_get('/', auth: 'gravel_lynx_wrong').code).to eq('401')
    end

    it 'denies malformed Authorization headers' do
      res = Net::HTTP.start('127.0.0.1', server.port) do |http|
        http.request(Net::HTTP::Get.new('/', 'Authorization' => 'Bearer nope'))
      end
      expect(res.code).to eq('401')
    end

    it 'rotates the password live' do
      server.set_password('cobalt_delta_fox')
      expect(http_get('/', auth: 'amber_river_owl').code).to eq('401')
      expect(http_get('/', auth: 'cobalt_delta_fox').code).to eq('200')
    end

    it 'generates a five-word underscore passphrase when none is given' do
      server.stop
      generated = server.start(host: '127.0.0.1', port: 0, interval: 3600)
      expect(generated).to match(/\A[a-z]+(?:_[a-z]+){4}\z/)
    end

    it 'keeps no plaintext password and hides it from status' do
      expect(server.status).not_to have_key(:password)
      expect(server.status[:auth_required]).to be(true)
      expect(server.instance_variable_get(:@password)).to be_nil
      server.set_password('cobalt_delta_fox')
      expect(server.instance_variable_get(:@password)).to be_nil
      expect(server.status).not_to have_key(:password)
    end

    it 'leaves the server restartable when the port is already bound' do
      server.stop
      blocker = TCPServer.new('127.0.0.1', 0)
      busy_port = blocker.addr[1]
      expect do
        server.start(host: '127.0.0.1', port: busy_port, interval: 3600, password: password)
      end.to raise_error(Errno::EADDRINUSE)
      expect(server.running?).to be(false)
      blocker.close
      expect(server.start(host: '127.0.0.1', port: 0, interval: 3600, password: password)).to eq(password)
      expect(server.running?).to be(true)
    end
  end

  describe 'circular route prevention (PR review)' do
    it 'never resolves a host to a pivot route announced by itself' do
      pivot = Struct.new(:address, :id).new('172.28.57.10', 7)
      routes = { '172.28.57.0/255.255.255.0' => 7 }
      expect(server.send(:find_pivot_for_host, pivot, routes)).to be_nil

      other = Struct.new(:address, :id).new('172.28.57.20', 9)
      expect(server.send(:find_pivot_for_host, other, routes)).to eq(7)
    end
  end

  describe 'websocket security (cross-site hijacking)' do
    it 'denies the upgrade without credentials' do
      expect(ws_handshake).to start_with('HTTP/1.1 401')
    end

    it 'denies the upgrade from a foreign origin' do
      expect(ws_handshake(auth: password, origin: 'http://evil.example.com')).to start_with('HTTP/1.1 403')
    end

    it 'rejects null origins' do
      expect(ws_handshake(auth: password, origin: 'null')).to start_with('HTTP/1.1 403')
    end

    it 'allows the upgrade with credentials and a same-host origin' do
      expect(ws_handshake(auth: password, origin: "http://127.0.0.1:#{server.port}")).to start_with('HTTP/1.1 101')
    end

    it 'allows the upgrade from any loopback spelling of the listener' do
      aggregate_failures do
        expect(ws_handshake(auth: password, origin: "http://localhost:#{server.port}")).to start_with('HTTP/1.1 101')
        expect(ws_handshake(auth: password, origin: "http://[::1]:#{server.port}")).to start_with('HTTP/1.1 101')
      end
    end
  end

  describe 'websocket keepalive' do
    it 'pings idle viewers so the frame deadline cannot reap them' do
      stub_const("#{described_class}::WEBSOCKET_PING_INTERVAL", 0.2)
      sock = ws_connect(auth: password)
      begin
        expect(Timeout.timeout(5) { ws_read_until_ping(sock) }).to be(true)
      ensure
        sock.close
      end
    end
  end

  describe 'origin validation' do
    it 'accepts only bare HTTP(S) origins' do
      aggregate_failures do
        expect { described_class.validate_origin!('192.168.1.5:4646') }.to raise_error(ArgumentError)
        expect { described_class.validate_origin!('ftp://example.com') }.to raise_error(ArgumentError)
        expect { described_class.validate_origin!('http://user:pass@example.com') }.to raise_error(ArgumentError)
        expect { described_class.validate_origin!('http://example.com/graph') }.to raise_error(ArgumentError)
        expect { described_class.validate_origin!('http://example.com/?q=1') }.to raise_error(ArgumentError)
      end
      expect(described_class.validate_origin!('http://127.0.0.1:4646').host).to eq('127.0.0.1')
    end

    it 'fails a malformed --origin start cleanly without leaving a server running' do
      server.stop
      expect do
        server.start(host: '127.0.0.1', port: 0, interval: 3600, password: password, origin: 'garbage')
      end.to raise_error(ArgumentError)
      expect(server.running?).to be(false)
    end
  end

  describe 'DNS rebinding defense' do
    it 'rejects requests with a foreign Host header' do
      expect(http_get('/', auth: password, host_header: 'evil.example.com:4646').code).to eq('403')
    end

    it 'accepts the loopback host names it was bound for' do
      expect(http_get('/', auth: password, host_header: "localhost:#{server.port}").code).to eq('200')
    end

    it 'accepts every loopback spelling of the bound listener' do
      aggregate_failures do
        expect(http_get('/', auth: password, host_header: "127.0.0.1:#{server.port}").code).to eq('200')
        expect(http_get('/', auth: password, host_header: "localhost:#{server.port}").code).to eq('200')
        expect(http_get('/', auth: password, host_header: "[::1]:#{server.port}").code).to eq('200')
      end
    end

    it 'accepts a port-less Host header when the origin uses the default port' do
      server.stop
      server.start(host: '127.0.0.1', port: 0, interval: 3600, password: password, origin: 'http://127.0.0.1')
      aggregate_failures do
        expect(http_get('/', auth: password, host_header: '127.0.0.1').code).to eq('200')
        expect(http_get('/', auth: password, host_header: 'localhost').code).to eq('200')
      end
    end
  end

  describe 'client tracking (network_map_clients)' do
    it 'records connected browsers with connection time and last activity' do
      sock = TCPSocket.new('127.0.0.1', server.port)
      req = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:#{server.port}\r\n" \
            "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" \
            "Sec-WebSocket-Version: 13\r\n" \
            "Authorization: Basic #{Base64.strict_encode64("user:#{password}")}\r\n" \
            "Origin: http://127.0.0.1:#{server.port}\r\n\r\n"
      sock.write(req)
      expect(sock.gets).to start_with('HTTP/1.1 101')

      info = nil
      Timeout.timeout(5) do
        loop do
          info = server.clients_info
          break unless info.empty?

          sleep 0.05
        end
      end
      aggregate_failures do
        expect(info.length).to eq(1)
        expect(info.first[:addr]).to eq('127.0.0.1')
        expect(info.first[:port]).to be_a(Integer)
        expect(info.first[:connected_at]).to be_a(Time)
        expect(info.first[:last_seen]).to be_a(Time)
      end

      sock.close
      Timeout.timeout(5) do
        loop do
          break if server.clients_info.empty?

          sleep 0.05
        end
      end
      expect(server.clients_info).to be_empty
    end
  end

  describe 'response headers (OWASP HTML5 Security Cheat Sheet)' do
    let(:res) { http_get('/', auth: password) }

    it 'denies framing' do
      expect(res['X-Frame-Options']).to eq('DENY')
      expect(res['Content-Security-Policy']).to include("frame-ancestors 'none'")
    end

    it 'sets referrer, sniffing, resource and caching policies' do
      expect(res['Referrer-Policy']).to eq('no-referrer')
      expect(res['X-Content-Type-Options']).to eq('nosniff')
      expect(res['Cross-Origin-Resource-Policy']).to eq('same-origin')
      expect(res['Cache-Control']).to eq('no-store')
    end

    it 'denies powerful browser features' do
      expect(res['Permissions-Policy']).to include('geolocation=()')
    end

    it 'never emits CORS headers' do
      %w[Access-Control-Allow-Origin Access-Control-Allow-Credentials Access-Control-Allow-Headers].each do |h|
        expect(res[h]).to be_nil
      end
    end
  end

  describe 'served page (OWASP HTML5 Security Cheat Sheet)' do
    let(:html) { Msf::Plugin::NetworkMapLive::INDEX_HTML }

    it 'uses no cross-document messaging' do
      expect(html).not_to include('postMessage(')
    end

    it 'uses no Server-Sent Events, workers, or geolocation APIs' do
      expect(html).not_to include('EventSource')
      expect(html).not_to include('new Worker')
      expect(html).not_to include('getCurrentPosition')
      expect(html).not_to include('watchPosition')
    end

    it 'stores no secrets in web storage' do
      keys = html.scan(/localStorage\.setItem\('([^']+)'/).flatten
      expect(keys - %w[msf-graph-theme]).to be_empty
      expect(html).not_to include('sessionStorage')
    end

    it 'never evaluates data as code' do
      expect(html).not_to include('eval(')
    end

    it 'marks new-window links rel=noopener noreferrer (tabnabbing)' do
      expect(html).to include('target="_blank" rel="noopener noreferrer"')
    end
  end
end
