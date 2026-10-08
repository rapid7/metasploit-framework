require_relative 'spec_helper'

RSpec.describe 'Garak model discovery' do
  subject(:mod) do
    garak_test_runner(Msf::Plugin::Garak::Runner)
  end

  before do
    mod.datastore['VERBOSE'] = true
    mod.datastore['TARGET_TYPE'] = 'ollama'
    mod.datastore['RHOSTS'] = '192.0.2.1'
    mod.datastore['RHOST'] = '192.0.2.1'
    allow(mod).to receive(:print_status)
  end

  %w[ollama ollama.OllamaGenerator ollama.OllamaGeneratorChat].each do |adapter|
    it "supports discovery for #{adapter}" do
      mod.datastore['TARGET_TYPE'] = adapter
      expect(mod.model_discovery_supported?).to be true
    end
  end

  it 'lists unique valid names without scanning or choosing the only model' do
    mod.datastore['TARGETURI'] = '/service/'
    response = Rex::Proto::Http::Response.new(200)
    response.body = { models: [{ name: 'example:3b' }, { name: 'example:3b' }, {}, nil, { name: 123 }] }.to_json
    expect(mod).to receive(:send_request_cgi).with('method' => 'GET', 'uri' => '/service/api/tags').and_return(response)
    expect(mod).not_to receive(:scan_garak)
    mod.run_host('192.0.2.1')
    expect(mod).to have_received(:print_status).with('Model: example:3b').once
    expect(mod.datastore['TARGET_NAME']).to be_blank
  end

  it 'does not query models when a target name is provided' do
    mod.datastore['TARGET_NAME'] = 'example:3b'
    expect(mod).not_to receive(:send_request_cgi)
    expect(mod).to receive(:scan_garak)
    mod.run_host('192.0.2.1')
  end

  it 'explains unsupported adapters' do
    mod.datastore['TARGET_TYPE'] = 'rest'
    mod.datastore['PROBES'] = 'probes.test.Blank'
    expect { mod.validate_scan }.to raise_error(Msf::Auxiliary::Failed, /Model discovery is not supported/)
  end

  it 'reports a missing response' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)
    expect { mod.list_target_names }.to raise_error(Msf::Auxiliary::Failed, /did not respond/)
  end

  it 'reports HTTP errors' do
    allow(mod).to receive(:send_request_cgi).and_return(Rex::Proto::Http::Response.new(401))
    expect { mod.list_target_names }.to raise_error(Msf::Auxiliary::Failed, /HTTP 401/)
  end

  ['invalid', '[]', '{}', '{"models":{}}'].each do |body|
    it "rejects invalid model data #{body}" do
      response = Rex::Proto::Http::Response.new(200)
      response.body = body
      allow(mod).to receive(:send_request_cgi).and_return(response)
      expect { mod.list_target_names }.to raise_error(Msf::Auxiliary::Failed, /expected a JSON model list/)
    end
  end

  it 'reports an empty list' do
    response = Rex::Proto::Http::Response.new(200)
    response.body = '{"models":[]}'
    allow(mod).to receive(:send_request_cgi).and_return(response)
    expect(mod).to receive(:print_warning).with(/No TARGET_NAME values/)
    mod.list_target_names
  end
end
