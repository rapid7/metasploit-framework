require 'spec_helper'

RSpec.describe 'Garak llama.cpp discovery' do
  include_context 'Msf::Simple::Framework#modules loading'
  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/garak/garak_llama') }
  let(:ip) { '192.0.2.1' }
  let(:document) do
    { 'data' => [{ 'id' => 'example', 'owned_by' => 'llamacpp' }], 'models' => [{ 'name' => 'example', 'capabilities' => ['completion'] }] }
  end
  let(:metadata) do
    {
      'probes' => { 'probes.test.Text' => { 'inputs' => ['text'] }, 'probes.test.Image' => { 'inputs' => %w[text image] } },
      'generators' => { 'openai.OpenAICompatible' => { 'inputs' => ['text'] } }
    }
  end

  def response(document, code = 200)
    result = Rex::Proto::Http::Response.new(code)
    result.body = document.to_json
    result
  end

  before do
    mod.datastore['VERBOSE'] = true
    mod.datastore['RHOSTS'] = ip
    mod.datastore['RHOST'] = ip
    mod.datastore['SUGGEST_PROBES'] = false
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_warning)
    allow(mod).to receive(:store_loot).and_return('/tmp/results.json')
  end

  it 'discovers models over HTTPS with a base path and bearer authentication' do
    mod.datastore['SSL'] = true
    mod.datastore['TARGETURI'] = '/llama/'
    mod.datastore['API_KEY'] = 'test-key'
    expect(mod).to receive(:send_request_cgi).with('method' => 'GET', 'uri' => '/llama/v1/models', 'headers' => { 'Authorization' => 'Bearer test-key' }).and_return(response(document))
    mod.run_host(ip)
    expect(mod).to have_received(:report_service).with(hash_including(name: 'https', info: 'llama.cpp'))
    expect(mod).to have_received(:print_status).with(a_string_including('TARGET_NAME', 'example'))
    expect(mod).to have_received(:print_status).with(a_string_including('TARGET_TYPE', 'openai.OpenAICompatible'))
    expect(mod).to have_received(:print_status).with(a_string_including('TARGETURI /llama/v1/'))
  end

  it 'does not identify another OpenAI-compatible service as llama.cpp' do
    document['data'][0]['owned_by'] = 'other'
    allow(mod).to receive(:send_request_cgi).and_return(response(document))
    mod.run_host(ip)
    expect(mod).not_to have_received(:report_service)
  end

  [401, 403].each do |code|
    it "explains authentication failure #{code}" do
      allow(mod).to receive(:send_request_cgi).and_return(response({}, code))
      expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /API_KEY/)
    end
  end

  it 'rejects malformed model lists' do
    allow(mod).to receive(:send_request_cgi).and_return(response('data' => [nil]))
    expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /invalid.*list/)
  end

  it 'handles an unreachable server' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)
    expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /did not respond/)
  end

  it 'suggests text probes, excludes images and persists compatibility results' do
    mod.datastore['SUGGEST_PROBES'] = true
    mod.instance_variable_set(:@probe_metadata, metadata)
    allow(mod).to receive(:send_request_cgi).and_return(response(document), response({}))
    mod.run_host(ip)
    expect(mod).to have_received(:print_status).with(a_string_including('Suggested probes', 'probes.test.Text'))
    expect(mod).to have_received(:report_note).with(hash_including(type: 'llama.garak.probes', data: hash_including('probes' => {
      'probes.test.Text' => { 'openai.OpenAICompatible' => 'suggested' },
      'probes.test.Image' => { 'openai.OpenAICompatible' => 'incompatible' }
    })))
  end

  it 'does not suggest image probes unsupported by the adapter even for a vision model' do
    props = { 'model_alias' => 'example', 'modalities' => { 'vision' => true } }
    caps = mod.llama_capabilities('example', document, props)
    expect(caps).to eq(%w[completion vision])
    result = mod.garak_probe_suggestions(caps, metadata, target_types: ['openai.OpenAICompatible'])
    expect(result['probes']['probes.test.Image']['openai.OpenAICompatible']).to eq('incompatible')
  end

  it 'does not apply one models properties to another' do
    props = { 'model_alias' => 'other', 'modalities' => { 'vision' => true } }
    expect(mod.llama_capabilities('example', document, props)).to eq(['completion'])
  end

  it 'retains uncertainty when capabilities are absent' do
    expect(mod.llama_capabilities('example', {}, {})).to be_nil
  end

  it 'retains model discovery when properties are denied' do
    mod.datastore['SUGGEST_PROBES'] = true
    mod.datastore['PROBE_FILTER'] = 'does-not-exist'
    mod.instance_variable_set(:@probe_metadata, metadata)
    allow(mod).to receive(:send_request_cgi).and_return(response(document), response({}, 403))
    mod.run_host(ip)
    expect(mod).to have_received(:print_warning).with(/properties are unavailable/)
    expect(mod).to have_received(:print_warning).with(/No probes matched/)
  end
end
