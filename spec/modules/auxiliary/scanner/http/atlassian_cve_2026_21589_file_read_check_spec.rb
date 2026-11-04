require 'spec_helper'

RSpec.describe 'Atlassian CVE-2026-21589 File Read Check' do
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

  let(:confluence_body) do
    '<web-app><listener-class>com.atlassian.confluence.impl.webapp.ServletsInitializer</listener-class></web-app>'
  end

  let(:bitbucket_body) do
    '<web-app><listener-class>com.atlassian.plugin.servlet.ResourceDownloadUtils</listener-class></web-app>'
  end

  before do
    mod.datastore['RHOST'] = host
    mod.datastore['RPORT'] = 80
    mod.datastore['TARGETURI'] = '/'
    mod.datastore['PRODUCT'] = 'Jira'
    mod.datastore['FILEPATH'] = ''
    allow(mod).to receive(:vprint_status)
  end

  describe '#check_host' do
    {
      'Jira' => :jira_body,
      'Confluence' => :confluence_body,
      'Bitbucket' => :bitbucket_body
    }.each do |product, body_method|
      it "confirms #{product} is vulnerable when its marker file is retrieved" do
        mod.datastore['PRODUCT'] = product
        check_response = instance_double(
          Rex::Proto::Http::Response,
          code: 200,
          body: public_send(body_method)
        )
        allow(mod).to receive(:send_request_cgi!).and_return(check_response)

        result = mod.check_host(host)

        expect(result.code).to eq('vulnerable')
      end
    end

    it 'returns Unknown when no response is received' do
      allow(mod).to receive(:send_request_cgi!).and_return(nil)

      expect(mod.check_host(host).code).to eq('unknown')
    end

    it 'returns Unknown when the response is not HTTP 200' do
      error_response = instance_double(
        Rex::Proto::Http::Response,
        code: 404,
        body: ''
      )
      allow(mod).to receive(:send_request_cgi!).and_return(error_response)

      expect(mod.check_host(host).code).to eq('unknown')
    end

    [301, 302, 401, 403, 404, 500].each do |status|
      it "returns Unknown when the marker request receives HTTP #{status}" do
        response = instance_double(
          Rex::Proto::Http::Response,
          code: status,
          body: jira_body
        )
        allow(mod).to receive(:send_request_cgi!).and_return(response)

        expect(mod.check_host(host).code).to eq('unknown')
      end
    end

    [nil, ''].each do |body|
      it "returns Unknown when the HTTP 200 marker response body is #{body.inspect}" do
        response = instance_double(
          Rex::Proto::Http::Response,
          code: 200,
          body: body
        )
        allow(mod).to receive(:send_request_cgi!).and_return(response)

        expect(mod.check_host(host).code).to eq('unknown')
      end
    end

    it 'returns Unknown when no supported product signature matches' do
      unrelated_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: '<html>Unrelated application</html>'
      )
      allow(mod).to receive(:send_request_cgi!).and_return(unrelated_response)

      expect(mod.check_host(host).code).to eq('unknown')
    end

    it 'falls through to Confluence in Auto mode' do
      mod.datastore['PRODUCT'] = 'Auto'
      unrelated_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: '<html>Unrelated application</html>'
      )
      confluence_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: confluence_body
      )
      allow(mod).to receive(:send_request_cgi!).and_return(unrelated_response, confluence_response)

      result = mod.check_host(host)

      expect(result.code).to eq('vulnerable')
      expect(mod).to have_received(:send_request_cgi!).twice
    end
  end
end
