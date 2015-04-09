
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'

describe Metasploit::Framework::LoginScanner::HTTP do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  subject do
    described_class.new
  end

  let(:response) { Rex::Proto::Http::Response.new(200, 'OK') }

  before(:each) do
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(response)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
  end

  describe '#send_request' do
    context 'when a valid request is sent' do
      it 'returns a response object' do
        expect(subject.send_request({'uri'=>'/'})).to be_kind_of(Rex::Proto::Http::Response)
      end
    end
  end

  describe '#get_hidden_inputs' do
    let(:response) do
      res = Rex::Proto::Http::Response.new(200, 'OK')
      res.body = %Q|
      <html>
      <head>
      <body>
      <form action="test.php">
        <input name="input_1" type="hidden" value="some_value_1" />
      </form>
      <form>
        <input name="input_1" type="hidden" value="some_value_1" />
        <INPUT name="input_2" type="hidden" value="" />
      </form>
      </body>
      </head>
      </htm>
      |
      res
    end


    context 'when an HTML page contains two forms containing hidden inputs' do
      it 'returns an array' do
        expect(subject.get_hidden_inputs(response)).to be_kind_of(Array)
      end

      it 'returns hashes in the array' do
        subject.get_hidden_inputs(response).each do |form|
          expect(form).to be_kind_of(Hash)
        end
      end

      it 'returns \'some_value_1\' in the input_1 hidden input from the first element' do
        expect(subject.get_hidden_inputs(response)[0]['input_1']).to eq('some_value_1')
      end

      it 'returns two hidden inputs in the second element' do
        expect(subject.get_hidden_inputs(response)[1].length).to eq(2)
      end

      it 'returns an empty string for the input_2 hidden input from the second element' do
        expect(subject.get_hidden_inputs(response)[1]['input_2']).to be_empty
      end
    end
  end

end
