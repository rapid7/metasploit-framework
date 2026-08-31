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
  end
end
