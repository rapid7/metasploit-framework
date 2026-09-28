require 'rex/proto/dns'

RSpec.describe Rex::Proto::DNS::Server do
  subject(:server) { described_class.new }

  let(:cli) { double('client', write: nil) }

  # a real, encodable query for a name that is in neither the cache nor
  # anything the stubbed resolver knows about
  def query_for(name)
    query = Dnsruby::Message.new
    query.add_question(Dnsruby::Name.create("#{name}."), Dnsruby::Types::A)
    query.encode
  end

  describe '#default_dispatch_request' do
    context 'when the forwarded response carries no answers' do
      before do
        # the resolver forwards the query and comes back empty, which is the
        # path that finalizes an empty response - the one that crashed
        empty_response = Dnsruby::Message.new
        server.fwd_res = double('resolver', send: empty_response)
      end

      it 'does not raise' do
        expect { server.default_dispatch_request(cli, query_for('empty.example.com')) }.not_to raise_error
      end

      it 'sends a well formed, encoded response back to the client' do
        expect(cli).to receive(:write) do |data|
          expect(data).to be_a(String)
          reply = Dnsruby::Message.decode(data)
          expect(reply.header.get_header_rcode).to eq(Dnsruby::RCode::NOERROR)
          expect(reply.header.qr).to eq(true)
        end
        server.default_dispatch_request(cli, query_for('empty.example.com'))
      end
    end

    context 'when the forwarded response carries an answer' do
      let(:answer) do
        Dnsruby::RR.create(name: 'poisoned.example.com.', type: 'A', address: '192.0.2.10')
      end

      before do
        # the resolver forwards the query and returns one answer, which is the
        # path that has to survive re-encoding intact
        forwarded = Dnsruby::Message.new
        forwarded.add_answer(answer)
        server.fwd_res = double('resolver', send: forwarded)
      end

      it 'encodes the answer inside the answer section rather than past the packet end' do
        # Regression: mutating a decoded request's @answer and re-encoding it
        # appended the answer bytes after the packet, so the reply decoded with
        # zero answers. Building a fresh response keeps the answer readable.
        expect(cli).to receive(:write) do |data|
          reply = Dnsruby::Message.decode(data)
          expect(reply.answer.count).to eq(1)
          expect(reply.answer.first.address.to_s).to eq('192.0.2.10')
        end
        server.default_dispatch_request(cli, query_for('poisoned.example.com'))
      end
    end

    context 'when one of several questions is served from cache' do
      it 'forwards only the uncached question and keeps the request questions intact' do
        # Regression: Dnsruby#dup is shallow, so deleting a served question from
        # the forwarded packet also emptied the original request's question list.
        # Only the uncached question should be forwarded, and both questions must
        # still be echoed back in the response.
        cached_answer = Dnsruby::RR.create(name: 'a.example.com.', type: 'A', address: '192.0.2.30')
        allow(server.cache).to receive(:find) do |qname, _qtype|
          qname.to_s == 'a.example.com' ? [cached_answer] : []
        end

        forwarded = Dnsruby::Message.new
        forwarded.add_answer(Dnsruby::RR.create(name: 'b.example.com.', type: 'A', address: '192.0.2.20'))
        resolver = double('resolver')
        server.fwd_res = resolver

        query = Dnsruby::Message.new
        query.add_question(Dnsruby::Name.create('a.example.com.'), Dnsruby::Types::A)
        query.add_question(Dnsruby::Name.create('b.example.com.'), Dnsruby::Types::A)

        expect(resolver).to receive(:send) do |fwd|
          expect(fwd.question.map { |q| q.qname.to_s }).to eq(['b.example.com'])
          forwarded
        end

        expect(cli).to receive(:write) do |data|
          reply = Dnsruby::Message.decode(data)
          expect(reply.question.map { |q| q.qname.to_s }).to contain_exactly('a.example.com', 'b.example.com')
          expect(reply.answer.map { |a| a.address.to_s }).to contain_exactly('192.0.2.30', '192.0.2.20')
        end
        server.default_dispatch_request(cli, query.encode)
      end
    end

    context 'response header flags' do
      # dispatch a query with a known Recursion Desired bit and decode the reply
      def dispatch_and_decode(rd:)
        query = Dnsruby::Message.new
        query.add_question(Dnsruby::Name.create('flags.example.com.'), Dnsruby::Types::A)
        query.header.rd = rd
        captured = nil
        allow(cli).to receive(:write) { |data| captured = Dnsruby::Message.decode(data) }
        server.default_dispatch_request(cli, query.encode)
        captured
      end

      it 'echoes the request Recursion Desired bit back to the client' do
        # Regression: the fresh response defaulted RD to false, dropping the
        # request's RD bit instead of echoing it.
        server.fwd_res = double('resolver', send: Dnsruby::Message.new)
        expect(dispatch_and_decode(rd: true).header.rd).to eq(true)
        expect(dispatch_and_decode(rd: false).header.rd).to eq(false)
      end

      it 'advertises Recursion Available when a forwarder is configured' do
        server.fwd_res = double('resolver', send: Dnsruby::Message.new)
        expect(dispatch_and_decode(rd: true).header.ra).to eq(true)
      end

      it 'does not advertise Recursion Available when forwarding is disabled' do
        server.fwd_res = nil
        expect(dispatch_and_decode(rd: true).header.ra).to eq(false)
      end
    end
  end

  describe '#monitor_listener' do
    let(:udp_sock) { double('udp_sock') }

    before do
      allow(server).to receive(:udp_sock).and_return(udp_sock)
      # make the otherwise-infinite loop run exactly one iteration
      allow(::IO).to receive(:select).and_return([[udp_sock], [], []])
    end

    def capture_client
      captured = nil
      allow(server).to receive(:dispatch_request) do |client, _data|
        captured = client
        throw :stop_listener
      end
      catch(:stop_listener) { server.send(:monitor_listener) }
      captured
    end

    it 'addresses the reply using the three-value recvfrom form (data, host, port)' do
      # Rex sockets return [data, host, port]; the reply must go to that host/port.
      allow(udp_sock).to receive(:recvfrom).with(65535).and_return(['REQ', '192.0.2.77', 5353])
      client = capture_client
      expect(client.peerhost).to eq('192.0.2.77')
      expect(client.peerport).to eq(5353)
    end

    it 'addresses the reply using the two-value recvfrom form (data, sockaddr array)' do
      # Raw Ruby UDPSocket returns [data, [family, port, name, ip]]; host/port
      # come out of the sockaddr array instead.
      allow(udp_sock).to receive(:recvfrom).with(65535).and_return(['REQ', ['AF_INET', 5353, 'host', '192.0.2.88']])
      client = capture_client
      expect(client.peerhost).to eq('192.0.2.88')
      expect(client.peerport).to eq(5353)
    end
  end
end
