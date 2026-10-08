require 'spec_helper'
require 'msf/core/auxiliary/garak'

RSpec.describe Msf::Auxiliary::Garak do
  subject(:helper) { Msf::Auxiliary.new.extend(described_class) }

  %w[ollama ollama.OllamaGeneratorChat ollama.OllamaGenerator].each do |adapter|
    it "recognizes the Ollama adapter #{adapter}" do
      expect(helper.ollama_target_type?(adapter)).to be true
      resolved = described_class::ENDPOINT_ALIASES.fetch(adapter, adapter)
      expect(described_class::ENDPOINT_OPTIONS.fetch(resolved)).to eq('host')
    end
  end

  it 'does not identify other adapters as Ollama' do
    expect(helper.ollama_target_type?('rest')).to be false
    expect(helper.ollama_target_type?('custom.Provider')).to be false
  end

  it 'parses and deduplicates probe names from colored CLI output' do
    output = "Banner\n\e[1mprobes: \e[0mdan.Dan_11_0 🌟\nprobes: dan.Dan_11_0\nprobes: test.Blank\n"
    expect(helper.plugin_names(output, 'probes')).to eq(%w[dan.Dan_11_0 test.Blank])
  end

  it 'uses the sibling checkout when GARAK_PATH is unset' do
    allow(helper).to receive(:datastore).and_return('GARAK_PATH' => nil, 'RunTimeout' => 30)
    allow(Gem).to receive(:win_platform?).and_return(false)
    allow(File).to receive(:file?).with(File.join(helper.default_garak_path, 'garak', '__main__.py')).and_return(true)
    expect(helper).to receive(:validate_garak_python).with(helper.default_garak_path)
    expect(helper.validate_garak_runtime).to eq(helper.default_garak_path)
  end

  describe '#validate_garak_python' do
    before do
      helper.datastore['PYTHON'] = '/tmp/garak-env/bin/python'
      helper.datastore['VERBOSE'] = true
    end

    it 'checks CLI startup using the configured interpreter and checkout' do
      expect(helper).to receive(:execute_garak).with(['/tmp/garak-env/bin/python', '-m', 'garak', '--version'], '/tmp/checkout', anything).and_return(double(success?: true))
      expect { helper.validate_garak_python('/tmp/checkout') }.not_to raise_error
    end

    it 'reports the missing dependency and how to select an environment' do
      allow(helper).to receive(:execute_garak) do |_command, _checkout, output|
        File.write(output, "Traceback (most recent call last):\nModuleNotFoundError: No module named 'xdg_base_dirs'\n")
        double(success?: false, exitstatus: 1)
      end
      expect { helper.validate_garak_python('/tmp') }.to raise_error(Msf::Auxiliary::Failed, %r{PYTHON=/tmp/garak-env/bin/python: ModuleNotFoundError:.*xdg_base_dirs.*garak_set PYTHON}m)
    end

    [Errno::ENOENT, Errno::EACCES, Errno::ENOEXEC].each do |error|
      it "explains an interpreter execution failure (#{error})" do
        allow(helper).to receive(:execute_garak).and_raise(error)
        expect { helper.validate_garak_python('/tmp') }.to raise_error(Msf::Auxiliary::Failed, /Cannot execute PYTHON=.*garak_set PYTHON/)
      end
    end

    it 'rejects an empty interpreter without spawning a process' do
      helper.datastore['PYTHON'] = ''
      expect(helper).not_to receive(:execute_garak)
      expect { helper.validate_garak_python('/tmp') }.to raise_error(Msf::Auxiliary::Failed, /PYTHON is empty/)
    end

    it 'reports a bounded startup timeout' do
      allow(helper).to receive(:execute_garak).and_return(nil)
      expect { helper.validate_garak_python('/tmp') }.to raise_error(Msf::Auxiliary::Failed, /startup check.*exceeded RunTimeout/)
    end
  end

  describe '#garak_probe_suggestions' do
    let(:metadata) do
      {
        'probes' => {
          'probes.test.Text' => { 'inputs' => ['text'] },
          'probes.test.Image' => { 'inputs' => %w[text image] },
          'probes.test.Audio' => { 'inputs' => %w[text audio] },
          'probes.test.Unknown' => {}
        },
        'generators' => {
          'ollama.OllamaGeneratorChat' => { 'inputs' => %w[text image] },
          'ollama.OllamaGenerator' => { 'inputs' => ['text'] }
        }
      }
    end

    it 'compares only the explicitly selected generator family' do
      metadata['generators']['openai.OpenAICompatible'] = { 'inputs' => ['text'] }
      result = helper.garak_probe_suggestions(['completion'], metadata, target_types: ['openai.OpenAICompatible'])
      expect(result['probes']['probes.test.Text']).to eq('openai.OpenAICompatible' => 'suggested')
      expect(result['probes']['probes.test.Image']).to eq('openai.OpenAICompatible' => 'incompatible')
    end

    it 'suggests text probes for a text model and excludes image requirements' do
      result = helper.garak_probe_suggestions(%w[completion tools], metadata)
      expect(result['input_types']).to eq(['text'])
      expect(result['probes']['probes.test.Text'].values).to eq(%w[suggested suggested])
      expect(result['probes']['probes.test.Image'].values).to eq(%w[incompatible incompatible])
      expect(result['probes']['probes.test.Unknown'].values).to eq(%w[unknown unknown])
    end

    it 'requires both the model and adapter to accept every probe input type' do
      result = helper.garak_probe_suggestions(%w[completion vision], metadata)
      expect(result['input_types']).to eq(%w[text image])
      expect(result['probes']['probes.test.Image']).to eq('ollama.OllamaGeneratorChat' => 'suggested', 'ollama.OllamaGenerator' => 'incompatible')
      expect(result['probes']['probes.test.Audio'].values).to eq(%w[incompatible incompatible])
    end

    it 'does not suggest generation probes for embedding-only models' do
      result = helper.garak_probe_suggestions(['embedding'], metadata)
      expect(result['probes']['probes.test.Text'].values).to eq(%w[incompatible incompatible])
    end

    [nil, [], ['completion', nil]].each do |capabilities|
      it "retains unknown compatibility for missing or invalid capabilities #{capabilities.inspect}" do
        result = helper.garak_probe_suggestions(capabilities, metadata)
        expect(result['probes'].values.flat_map(&:values).uniq).to eq(['unknown'])
      end
    end

    it 'does not assume missing adapter metadata supports an input type' do
      metadata['generators'] = {}
      result = helper.garak_probe_suggestions(['completion'], metadata)
      expect(result['probes']['probes.test.Text'].values).to eq(%w[unknown unknown])
    end

    it 'does not silently exclude new capability types' do
      metadata['generators'].transform_values! { |_| { 'inputs' => %w[text audio] } }
      result = helper.garak_probe_suggestions(%w[completion future_audio], metadata)
      expect(result['probes']['probes.test.Audio'].values).to eq(%w[unknown unknown])
    end
  end

  describe '#garak_probe_metadata' do
    before do
      helper.datastore['VERBOSE'] = true
      helper.datastore['PYTHON'] = 'python3'
      allow(helper).to receive(:validate_garak_runtime).and_return('/tmp')
    end

    it 'uses the metadata helper and reads its separate JSON output' do
      metadata = { 'probes' => { 'probes.test.Text' => { 'inputs' => ['text'] } }, 'generators' => {} }
      expect(helper).to receive(:execute_garak) do |command, checkout, _output|
        expect(checkout).to eq('/tmp')
        expect(command[1]).to end_with('/auxiliary/garak/probe_metadata.py')
        File.write(command[2], metadata.to_json)
        double(success?: true)
      end
      expect(helper.garak_probe_metadata).to eq(metadata)
    end

    it 'reports a timed-out metadata process' do
      allow(helper).to receive(:execute_garak).and_return(nil)
      expect { helper.garak_probe_metadata }.to raise_error(Msf::Auxiliary::Failed, /exceeded RunTimeout/)
    end

    ['invalid', '{}', '{"probes":{},"generators":{}}'].each do |output|
      it "rejects invalid metadata #{output}" do
        allow(helper).to receive(:execute_garak) do |command, _checkout, _log|
          File.write(command[2], output)
          double(success?: true)
        end
        expect { helper.garak_probe_metadata }.to raise_error(Msf::Auxiliary::Failed, /metadata/)
      end
    end
  end
  it 'registers YAML output disabled by default' do
    helper.register_garak_yaml_option
    expect(helper.datastore['OUTPUT_YAML']).to be false
  end

  it 'serializes a plain safe YAML configuration without mutating its input' do
    config = { 'plugins' => { 'generators' => { 'rest' => { 'RestGenerator' => { 'uri' => 'http://192.0.2.1/', 'headers' => { 'x-api-key' => '$KEY' } } } } } }
    original = Marshal.load(Marshal.dump(config))
    allow(helper).to receive(:print_good)
    allow(helper).to receive(:print_status)
    expect(helper).to receive(:store_loot) do |type, mime, host, yaml, filename, _description|
      expect(type).to eq('example.garak.config.yaml')
      expect(mime).to eq('application/x-yaml')
      expect(host).to eq('192.0.2.1')
      expect(filename).to end_with('.yaml')
      expect(YAML.safe_load(yaml)).to eq('plugins' => config['plugins'].merge('target_type' => 'rest.RestGenerator', 'target_name' => 'http://192.0.2.1/'))
      '/tmp/example.yaml'
    end
    expect(helper.store_garak_yaml(ip: '192.0.2.1', namespace: 'example', config: config, target_type: 'rest.RestGenerator', target_name: 'http://192.0.2.1/')).to eq('/tmp/example.yaml')
    expect(helper).to have_received(:print_status).with('Use garak_scan TARGET_TYPE=rest.RestGenerator TARGET_NAME=http://192.0.2.1/ CONFIG_FILE=/tmp/example.yaml PROBES=probes.test.Blank PYTHON=python3 RunTimeout=300 VERBOSE=true')
    expect(helper).to have_received(:print_status).with('Or run in a terminal: python3 -m garak --config /tmp/example.yaml --spec probes.test.Blank')
    expect(config).to eq(original)
  end
  describe '#print_garak_scan_command' do
    it 'quotes complete scan settings and includes supplied credentials' do
      helper.datastore['PYTHON'] = '/path with spaces/python'
      helper.datastore['GARAK_PATH'] = '/path with spaces/garak'
      key = 'key with spaces;$(literal)'
      message = nil
      allow(helper).to receive(:print_status) { |value| message = value }
      helper.print_garak_scan_command(config_path: '/tmp/config file.json', target_type: 'rest.RestGenerator', target_name: 'http://192.0.2.1/run', rest_api_key: key)
      expect(Shellwords.split(message.delete_prefix('Use '))).to include('garak_scan', "REST_API_KEY=#{key}", 'PYTHON=/path with spaces/python', 'GARAK_PATH=/path with spaces/garak', 'CONFIG_FILE=/tmp/config file.json', 'PROBES=probes.test.Blank', 'RunTimeout=300', 'VERBOSE=true')
    end

    it 'omits an absent credential' do
      expect(helper).to receive(:print_status) { |message| expect(message).not_to include('REST_API_KEY=') }
      helper.print_garak_scan_command(config_path: '/tmp/config.json', target_type: 'rest.RestGenerator', target_name: 'http://192.0.2.1/run')
    end

    it 'allocates five minutes per distinct probe without counting overlapping family selectors' do
      expect(helper).to receive(:print_status) { |message| expect(Shellwords.split(message.delete_prefix('Use '))).to include('RunTimeout=600') }
      helper.print_garak_scan_command(config_path: '/tmp/config.yaml', target_type: 'rest.RestGenerator', target_name: 'http://192.0.2.1/run', probes: 'probes.dan,probes.dan.Dan_11_0,probes.dan.AntiDAN,probes.dan.Dan_11_0')
    end
  end

  ['/path/to/garak/bin/python', '/path with spaces/garak/bin/python'].each do |python|
    it "preserves the scanner interpreter in copyable commands for #{python}" do
      helper.datastore['PYTHON'] = python
      config = { 'plugins' => {}, 'run' => { 'spec' => { 'include' => ['probes.test.Blank'] } } }
      messages = []
      allow(helper).to receive(:store_loot).and_return('/tmp/config.yaml')
      allow(helper).to receive(:print_good)
      allow(helper).to receive(:print_status) { |message| messages << message }
      helper.store_garak_yaml(ip: '192.0.2.1', namespace: 'example', config: config, target_type: 'rest.RestGenerator', target_name: 'http://192.0.2.1/')
      scan = messages.find { |message| message.start_with?('Use garak_scan') }.delete_prefix('Use ')
      expect(Shellwords.split(scan)).to include("PYTHON=#{python}")
      terminal = messages.find { |message| message.start_with?('Or run in a terminal:') }.delete_prefix('Or run in a terminal: ')
      expect(Shellwords.split(terminal)).to eq([python, '-m', 'garak', '--config', '/tmp/config.yaml'])
    end
  end
end
