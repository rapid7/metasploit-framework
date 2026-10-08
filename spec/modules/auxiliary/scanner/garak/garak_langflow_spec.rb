require 'spec_helper'

RSpec.describe 'Garak Langflow discovery' do
  include_context 'Msf::Simple::Framework#modules loading'
  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/garak/garak_langflow') }
  let(:ip) { '192.0.2.1' }
  let(:flow_id) { '12345678-1234-1234-1234-123456789abc' }
  let(:flow) do
    {
      'id' => flow_id, 'name' => 'Example agent', 'data' => {
        'nodes' => [
          { 'id' => 'ChatInput-in', 'data' => { 'type' => 'ChatInput' } },
          { 'id' => 'CSVAgent-agent', 'data' => { 'type' => 'CSVAgent', 'node' => { 'template' => { 'api_key' => 'secret-not-for-loot' } } } },
          { 'id' => 'ChatOutput-out', 'data' => { 'type' => 'ChatOutput' } }
        ]
      }
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
    allow(mod).to receive(:store_loot).and_return('/tmp/langflow-config.json')
    allow(mod).to receive(:send_request_cgi).and_return(response('package' => 'Langflow', 'version' => '1.2.0'), response([flow]))
  end

  it 'saves a usable REST template without executing flows or leaking keys' do
    mod.datastore['API_KEY'] = 'discovery-secret'
    mod.run_host(ip)
    expect(mod).to have_received(:send_request_cgi).with(hash_including('method' => 'GET', 'headers' => { 'x-api-key' => 'discovery-secret' })).twice
    config = mod.generator_config(mod.flow_target(flow))
    generator = config.dig('plugins', 'generators', 'rest', 'RestGenerator')
    expect(generator['request_timeout']).to eq(300)
    expect(generator['uri']).to eq("http://#{ip}:7860/api/v1/run/#{flow_id}")
    expect(generator['req_template_json_object']).to include('input_value' => '$INPUT', 'output_component' => 'ChatOutput-out', 'input_type' => 'chat')
    expect(generator['response_json_field']).to eq('$.outputs[*].outputs[*].results.message.text')
    expect(generator['headers']['x-api-key']).to eq('$KEY')
    expect(config.to_json).not_to include('discovery-secret', 'secret-not-for-loot')
    expect(mod).to have_received(:store_loot).with('langflow.garak.config', 'application/json', ip, JSON.pretty_generate(config), "langflow_#{flow_id}_garak.json", anything)
    expect(mod).to have_received(:print_status).with(a_string_including('Candidate target types', 'TARGET_TYPE', 'rest.RestGenerator'))
    expect(mod).to have_received(:print_status).with(a_string_including('TARGET_NAME', generator['uri'], flow_id, 'Example agent'))
    expect(mod).to have_received(:report_note).with(hash_including(type: 'langflow.garak.targets', data: hash_including(targets: [hash_including(components: %w[CSVAgent ChatInput ChatOutput])])))
  end

  it 'saves a customized request timeout' do
    mod.datastore['REST_TIMEOUT'] = 600
    expect(mod.generator_config(mod.flow_target(flow)).dig('plugins', 'generators', 'rest', 'RestGenerator', 'request_timeout')).to eq(600)
  end

  it 'supports HTTPS, a base path and reading one flow' do
    mod.datastore['SSL'] = true
    mod.datastore['TARGETURI'] = '/langflow/'
    mod.datastore['FLOW_ID'] = flow_id
    allow(mod).to receive(:send_request_cgi).and_return(response('package' => 'Langflow', 'version' => '1.10.0'), response(flow))
    mod.run_host(ip)
    expect(mod).to have_received(:send_request_cgi).with(hash_including('uri' => "/langflow/api/v1/flows/#{flow_id}"))
    expect(mod.flow_target(flow)[:endpoint]).to eq("https://#{ip}:7860/langflow/api/v1/run/#{flow_id}")
  end

  it 'rejects an unrelated version endpoint' do
    allow(mod).to receive(:send_request_cgi).and_return(response('package' => 'Other', 'version' => '1.2.0'))
    mod.run_host(ip)
    expect(mod).not_to have_received(:report_service)
    expect(mod).not_to have_received(:store_loot)
  end

  [401, 403].each do |code|
    it "explains denied discovery with HTTP #{code}" do
      allow(mod).to receive(:send_request_cgi).and_return(response({}, code))
      expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /API_KEY/)
    end
  end

  it 'handles an unreachable endpoint' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)
    expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /did not respond/)
  end

  it 'rejects malformed flow inventories' do
    allow(mod).to receive(:read_api).and_return([nil])
    expect { mod.discover_flows }.to raise_error(Msf::Auxiliary::Failed, /flow objects/)
  end

  it 'reports an empty inventory without saving a config' do
    allow(mod).to receive(:discover_flows).and_return([])
    mod.run_host(ip)
    expect(mod).not_to have_received(:store_loot)
    expect(mod).to have_received(:print_warning).with(/No saved flows/)
  end

  it 'skips standalone components' do
    allow(mod).to receive(:discover_flows).and_return([flow])
    flow['is_component'] = true
    mod.run_host(ip)
    expect(mod).not_to have_received(:store_loot)
  end

  it 'does not generate a config for missing or malformed graph data' do
    allow(mod).to receive(:discover_flows).and_return([flow])
    flow['data'] = { 'nodes' => [nil, {}, { 'data' => nil }] }
    mod.run_host(ip)
    expect(mod).not_to have_received(:store_loot)
  end

  it 'requires an explicit selection for multiple outputs' do
    allow(mod).to receive(:discover_flows).and_return([flow])
    flow['data']['nodes'] << { 'id' => 'TextOutput-out', 'data' => { 'type' => 'TextOutput' } }
    mod.run_host(ip)
    expect(mod).not_to have_received(:store_loot)
    mod.datastore['OUTPUT_COMPONENT'] = 'TextOutput-out'
    expect(mod.flow_target(flow)).to include(output_type: 'text', output_component: 'TextOutput-out')
    mod.datastore['OUTPUT_COMPONENT'] = 'does-not-exist'
    expect(mod.flow_target(flow)[:output_type]).to be_nil
  end

  it 'supports text flows but leaves multiple inputs unconfigured' do
    flow['data']['nodes'][0]['data']['type'] = 'TextInput'
    expect(mod.flow_target(flow)[:input_type]).to eq('text')
    flow['data']['nodes'] << { 'id' => 'ChatInput-other', 'data' => { 'type' => 'ChatInput' } }
    expect(mod.flow_target(flow)[:input_type]).to be_nil
  end

  it 'excludes examples by default and can include them explicitly' do
    expect(mod).to receive(:send_request_cgi).with(hash_including('vars_get' => hash_including('get_all' => 'true', 'remove_example_flows' => 'true'))).and_return(response([]))
    mod.discover_flows
    mod.datastore['INCLUDE_EXAMPLES'] = true
    expect(mod).to receive(:send_request_cgi).with(hash_including('vars_get' => hash_including('remove_example_flows' => 'false'))).and_return(response([]))
    mod.discover_flows
  end
  it 'writes an optional Garak YAML configuration with the discovered target' do
    mod.datastore['OUTPUT_YAML'] = true
    mod.datastore['REST_TIMEOUT'] = 600
    mod.datastore['SSL'] = true
    mod.datastore['RPORT'] = 8443
    mod.datastore['TARGETURI'] = '/provider/'
    saved = nil
    allow(mod).to receive(:store_loot) do |*args|
      saved = args
      '/tmp/target.yaml'
    end
    mod.run_host(ip)
    expect(saved[1]).to eq('application/x-yaml')
    expect(saved[4]).to end_with('.yaml')
    config = YAML.safe_load(saved[3])
    expect(config.dig('plugins', 'generators', 'rest', 'RestGenerator', 'request_timeout')).to eq(600)
    expect(config.dig('plugins', 'target_type')).to eq('rest.RestGenerator')
    expect(config.dig('plugins', 'target_name')).to eq("https://#{ip}:8443/provider/api/v1/run/#{flow_id}")
    expect(mod).to have_received(:print_status).with(a_string_including('Candidate target types', 'TARGET_TYPE', 'rest.RestGenerator'))
    expect(mod).to have_received(:print_status).with(a_string_including('TARGET_NAME', config.dig('plugins', 'target_name'), flow_id, 'Example agent'))
    expect(config.dig('plugins', 'generators', 'rest', 'RestGenerator', 'req_template_json_object', 'input_value')).to eq('$INPUT')
    expect(config.dig('plugins', 'generators', 'rest', 'RestGenerator', 'headers', 'x-api-key')).to eq('$KEY')
  end

  it 'discovers flows without FLOW_ID when the inventory is gzip compressed' do
    inventory = response([flow])
    inventory.headers['Content-Encoding'] = 'gzip'
    inventory.body = Zlib.gzip(inventory.body)
    allow(mod).to receive(:send_request_cgi).and_return(response('package' => 'Langflow', 'version' => '1.10.0'), inventory)
    expect(mod.datastore['FLOW_ID']).to be_nil
    mod.run_host(ip)
    expect(mod).to have_received(:store_loot).with('langflow.garak.config', 'application/json', ip, anything, "langflow_#{flow_id}_garak.json", anything)
    expect(mod).to have_received(:report_note).with(hash_including(data: hash_including(targets: [hash_including(id: flow_id)])))
  end

  it 'explains invalid gzip data rather than reporting an invalid flow list' do
    inventory = response([flow])
    inventory.headers['Content-Encoding'] = 'gzip'
    allow(mod).to receive(:send_request_cgi).and_return(inventory)
    expect { mod.discover_flows }.to raise_error(Msf::Auxiliary::Failed, /invalid gzip data/)
  end
  it 'lists local probes for configured flows and applies a case-insensitive filter on each run' do
    mod.datastore['SUGGEST_PROBES'] = true
    allow(mod).to receive(:available_plugins).with('probes').and_return(%w[test.Blank dan.Dan_11_0 visual_jailbreak.Test])
    allow(mod).to receive(:read_api).and_return({ 'package' => 'Langflow', 'version' => '1.10.0' }, [flow], { 'package' => 'Langflow', 'version' => '1.10.0' }, [flow])
    mod.datastore['PROBE_FILTER'] = 'DAN'
    mod.run_host(ip)
    expect(mod).to have_received(:print_status).with('Probe: probes.dan.Dan_11_0').once
    expect(mod).not_to have_received(:print_status).with('Probe: probes.test.Blank')
    mod.datastore['PROBE_FILTER'] = 'test.Blank'
    mod.run_host(ip)
    expect(mod).to have_received(:print_status).with('Probe: probes.test.Blank').once
    expect(mod).to have_received(:available_plugins).with('probes').twice
    expect(mod).not_to have_received(:print_status).with('Probe: probes.visual_jailbreak.Test')
  end

  it 'discovers configured flows without accessing local Garak when suggestions are disabled' do
    expect(mod).not_to receive(:available_plugins)
    mod.run_host(ip)
    expect(mod).to have_received(:store_loot)
  end

  it 'skips local probe listing when no flow can be configured' do
    mod.datastore['SUGGEST_PROBES'] = true
    flow['data'] = {}
    allow(mod).to receive(:discover_flows).and_return([flow])
    expect(mod).not_to receive(:available_plugins)
    mod.run_host(ip)
  end

  it 'explains how to resolve a missing probe-listing executable' do
    mod.datastore['SUGGEST_PROBES'] = true
    allow(mod).to receive(:available_plugins).and_raise(Errno::ENOENT)
    expect { mod.run_host(ip) }.to raise_error(Msf::Auxiliary::Failed, /disable SUGGEST_PROBES/)
  end
  it 'writes the filtered probe selections into YAML and lists the same probes' do
    mod.datastore['OUTPUT_YAML'] = true
    mod.datastore['SUGGEST_PROBES'] = true
    mod.datastore['PROBE_FILTER'] = 'DAN'
    allow(mod).to receive(:available_plugins).with('probes').and_return(%w[test.Blank dan.Dan_11_0 dan.AntiDAN])
    saved = nil
    allow(mod).to receive(:store_loot) do |*args|
      saved = args
      '/tmp/target.yaml'
    end
    mod.run_host(ip)
    expect(YAML.safe_load(saved[3]).dig('run', 'spec', 'include')).to eq(%w[probes.dan.Dan_11_0 probes.dan.AntiDAN])
    expect(mod).to have_received(:available_plugins).with('probes').once
    expect(mod).to have_received(:print_status).with('Probe: probes.dan.Dan_11_0')
    expect(mod).to have_received(:print_status).with('Probe: probes.dan.AntiDAN')
    expect(mod).to have_received(:print_status).with('Or run in a terminal: python3 -m garak --config /tmp/target.yaml')
    expect(mod).to have_received(:print_status).with(a_string_including('PROBES=probes.dan.Dan_11_0,probes.dan.AntiDAN'))
  end

  it 'explicitly selects no probes in YAML when the filter has no matches' do
    mod.datastore['OUTPUT_YAML'] = true
    mod.datastore['SUGGEST_PROBES'] = true
    mod.datastore['PROBE_FILTER'] = 'no-such-probe'
    allow(mod).to receive(:available_plugins).with('probes').and_return(['test.Blank'])
    expect(mod).to receive(:store_loot) do |*args|
      expect(YAML.safe_load(args[3]).dig('run', 'spec', 'include')).to eq(['probes.none'])
      '/tmp/target.yaml'
    end
    mod.run_host(ip)
  end
end
