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
  end
end
