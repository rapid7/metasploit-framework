require 'spec_helper'
require 'metasploit/framework/login_scanner/wordpress_multicall'

RSpec.describe Metasploit::Framework::LoginScanner::WordpressMulticall do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  subject do
    described_class.new
  end

  let(:username) do
    'username'
  end

  let(:good_password) do
    'goodpassword'
  end

  let(:passwords) do
    [good_password]
  end

  let(:good_response) do
    %Q|<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><array><data>
  <value><array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://192.168.1.202/wordpress/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Test</string></value></member>
  <member><name>xmlrpc</name><value><string>http://192.168.1.202/wordpress/xmlrpc.php</string></value></member>
</struct></value>
</data></array></value>
</data></array></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
    |
  end

  let(:response) do
    r = Rex::Proto::Http::Response.new(200, 'OK')
    r.body = good_response
    r
  end

  before(:each) do
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:send_recv).with(any_args).and_return(response)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:set_config).with(any_args)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:close)
    allow_any_instance_of(Rex::Proto::Http::Client).to receive(:connect)
  end

  before do
    subject.instance_variable_set(:@passwords, passwords)
    subject.set_default
  end

  describe '#generate_xml' do
    context 'when a username is given' do
      it 'returns an array' do
        expect(subject.generate_xml(username)).to be_kind_of(Array)
      end

      it 'contains our username' do
        xml = subject.generate_xml(username).first
        expect(xml).to include('<?xml version="1.0"?>')
      end
    end
  end

  describe '#attempt_login' do
    context 'when the credential is valid' do
      it 'returns a Result object indicating a successful login' do
        cred_obj = Metasploit::Framework::Credential.new(public: username, private: good_password)
        result = subject.attempt_login(cred_obj)
        expect(result).to be_kind_of(::Metasploit::Framework::LoginScanner::Result)
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end
    end
  end

  describe '#send_wp_request' do
    context 'when a request is sent' do
      it 'sets @res with an HTTP response object' do
        subject.send_wp_request('xml')
        expect(subject.instance_variable_get(:@res)).to be_kind_of(Rex::Proto::Http::Response)
      end

      it 'sets @res with an XML document' do
        subject.send_wp_request('xml')
        expect(subject.instance_variable_get(:@res).body).to include('<?xml version="1.0" encoding="UTF-8"?>')
      end
    end
  end

end
