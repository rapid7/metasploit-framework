require 'spec_helper'

RSpec.describe 'Garak Ollama target discovery' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/garak/garak_ollama')
  end

  let(:ip) { '192.0.2.1' }

  def response(body, code = 200)
    result = Rex::Proto::Http::Response.new(code)
    result.body = body
    result
  end

  before do
    mod.datastore['VERBOSE'] = true
    mod.datastore['SUGGEST_PROBES'] = false
    mod.datastore['RHOSTS'] = ip
    mod.datastore['RHOST'] = ip
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_warning)
  end

  it 'discovers unique model names and records service and garak settings over HTTPS at a base path' do
    mod.datastore['SSL'] = true
    mod.datastore['RPORT'] = 8443
    mod.datastore['TARGETURI'] = '/ollama/'
    expect(mod).to receive(:send_request_cgi).with({ 'uri' => '/ollama/' }).ordered.and_return(response("Ollama is running\n"))
    models = { models: [{ name: 'example:3b' }, { name: 'example:3b' }, { name: 'another:7b' }] }
    expect(mod).to receive(:send_request_cgi).with({ 'uri' => '/ollama/api/tags' }).ordered.and_return(response(models.to_json))
    mod.run_host(ip)
    expect(mod).to have_received(:report_service).with(host: ip, port: 8443, proto: 'tcp', name: 'https', info: 'Ollama')
    expect(mod).to have_received(:print_status).with(a_string_including('Available target names', 'TARGET_NAME', 'example:3b', 'another:7b')).once
    expect(mod).to have_received(:print_status).with(a_string_including('Candidate target types', 'TARGET_TYPE', 'ollama.OllamaGeneratorChat', 'ollama.OllamaGenerator', 'Alias for')).once
    expect(mod).to have_received(:report_note).with(hash_including(type: 'ollama.garak.targets', update: :unique_data, data: hash_including(target_names: %w[another:7b example:3b])))
  end

  [nil, 'Unrelated service', '{"version":"1.0"}', '<html>Ollama is running</html>'].each do |body|
    it "does not report an Ollama service for #{body.inspect}" do
      expect(mod).to receive(:send_request_cgi).once.and_return(body.nil? ? nil : response(body))
      mod.run_host(ip)
      expect(mod).not_to have_received(:report_service)
      expect(mod).not_to have_received(:report_note)
    end
  end

  it 'does not accept an error response as a service fingerprint' do
    expect(mod).to receive(:send_request_cgi).once.and_return(response('Ollama is running', 403))
    mod.run_host(ip)
    expect(mod).not_to have_received(:report_service)
  end

  it 'reports an empty model inventory without inventing model names' do
    allow(mod).to receive(:send_request_cgi).and_return(response('Ollama is running'), response('{"models":[]}'))
    mod.run_host(ip)
    expect(mod).to have_received(:print_warning).with(/No TARGET_NAME values/)
    expect(mod).to have_received(:report_note).with(hash_including(data: hash_including(target_names: [])))
  end

  [nil, 'invalid', '[]', '{}', '{"models":[{}]}', '{"models":[{"name":123}]}'].each do |body|
    it "reports a failed model query for #{body.inspect}" do
      allow(mod).to receive(:send_request_cgi).and_return(response('Ollama is running'), body.nil? ? nil : response(body))
      expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /model discovery failed/)
      expect(mod).not_to have_received(:report_note)
    end
  end

  it 'explains authentication failures from the model API' do
    allow(mod).to receive(:send_request_cgi).and_return(response('Ollama is running'), response('', 401))
    expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /HTTP 401.*authentication/)
  end

  it 'handles connection failures without reporting targets' do
    allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionError, 'Connection refused')
    expect(mod).to receive(:vprint_error).with(/Ollama discovery request failed:/)
    mod.run_host(ip)
    expect(mod).not_to have_received(:report_note)
  end

  it 'requires a remote host for discovery' do
    mod.datastore['RHOSTS'] = nil
    expect { mod.options.validate(mod.datastore) }.to raise_error(Msf::OptionValidateError)
  end

  describe 'capability-based probe suggestions' do
    let(:metadata) do
      {
        'garak_version' => 'test',
        'probes' => {
          'probes.test.Text' => { 'inputs' => ['text'] },
          'probes.test.Image' => { 'inputs' => %w[text image] }
        },
        'generators' => {
          'ollama.OllamaGeneratorChat' => { 'inputs' => ['text'] },
          'ollama.OllamaGenerator' => { 'inputs' => ['text'] }
        }
      }
    end

    before do
      mod.datastore['SUGGEST_PROBES'] = true
      mod.instance_variable_set(:@probe_metadata, metadata)
      allow(mod).to receive(:store_loot).and_return('/tmp/suggestions.json')
    end

    it 'queries each unique model with POST api/show and records compatible probes' do
      mod.datastore['TARGETURI'] = '/ollama/'
      expect(mod).to receive(:send_request_cgi).with({ 'uri' => '/ollama/' }).ordered.and_return(response('Ollama is running'))
      expect(mod).to receive(:send_request_cgi).with({ 'uri' => '/ollama/api/tags' }).ordered.and_return(response('{"models":[{"name":"model:3b"},{"name":"model:3b"}]}'))
      expect(mod).to receive(:send_request_cgi).with({ 'method' => 'POST', 'uri' => '/ollama/api/show', 'ctype' => 'application/json', 'data' => '{"model":"model:3b"}' }).once.ordered.and_return(response('{"capabilities":["completion","tools"]}'))
      mod.run_host(ip)
      expect(mod).to have_received(:report_note).with(hash_including(type: 'ollama.garak.probes', data: hash_including('input_types' => ['text'], 'target_name' => 'model:3b')))
      expect(mod).to have_received(:print_status).with(/probes.test.Text/)
      expect(mod).not_to have_received(:print_status).with(/probes.test.Image/)
      expect(mod).to have_received(:store_loot).with('ollama.garak.probes', 'application/json', ip, a_string_including('incompatible'), 'garak-probe-suggestions.json')
    end

    it 'filters suggestions without assuming model names imply capabilities' do
      mod.datastore['PROBE_FILTER'] = 'TEXT'
      allow(mod).to receive(:model_capabilities).and_return(['completion'])
      mod.suggest_model_probes(ip, 'vision-in-name:latest')
      expect(mod).to have_received(:report_note).with(hash_including(data: hash_including('probes' => {
        'probes.test.Text' => { 'ollama.OllamaGeneratorChat' => 'suggested', 'ollama.OllamaGenerator' => 'suggested' }
      })))
    end

    [nil, '{}', '{"capabilities":[]}', 'invalid'].each do |body|
      it "keeps compatibility unknown when capability discovery fails with #{body.inspect}" do
        allow(mod).to receive(:send_request_cgi).and_return(body.nil? ? nil : response(body))
        mod.suggest_model_probes(ip, 'model:3b')
        expect(mod).to have_received(:print_warning).with(/Capabilities.*unknown/)
        expect(mod).to have_received(:print_status).with(/0 suggested, 2 with unknown compatibility/)
      end
    end

    it 'handles authentication errors without losing target discovery results' do
      allow(mod).to receive(:send_request_cgi).and_return(response('', 401))
      expect(mod.model_capabilities('model:3b')).to be_nil
      expect(mod).to have_received(:print_warning).with(/HTTP 401/)
    end

    it 'handles connection errors during capability discovery' do
      allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionError)
      expect(mod.model_capabilities('model:3b')).to be_nil
      expect(mod).to have_received(:print_warning).with(/Capabilities.*unknown/)
    end
  end
  it 'writes an optional Garak YAML configuration with the discovered target' do
    mod.datastore['OUTPUT_YAML'] = true
    mod.datastore['SSL'] = true
    mod.datastore['RPORT'] = 8443
    mod.datastore['TARGETURI'] = '/provider/'
    allow(mod).to receive(:send_request_cgi).and_return(response('Ollama is running'), response({ models: [{ name: 'example:3b' }] }.to_json))
    saved = nil
    allow(mod).to receive(:store_loot) do |*args|
      saved = args
      '/tmp/target.yaml'
    end
    mod.run_host(ip)
    expect(saved[1]).to eq('application/x-yaml')
    expect(saved[4]).to end_with('.yaml')
    config = YAML.safe_load(saved[3])
    expect(config.dig('plugins', 'target_type')).to eq('ollama.OllamaGeneratorChat')
    expect(config.dig('plugins', 'target_name')).to eq('example:3b')
    expect(config.dig('plugins', 'generators', 'ollama', 'OllamaGeneratorChat', 'host')).to eq("https://#{ip}:8443/provider/")
  end
end
