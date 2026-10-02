require 'spec_helper'

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
    expect(helper.validate_garak_runtime).to eq(helper.default_garak_path)
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
end
