require 'spec_helper'

RSpec.describe 'Garak probe listing' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/garak/garak_integration')
  end

  before do
    mod.datastore['VERBOSE'] = true
  end

  describe 'scan target validation' do
    [nil, '', '   '].each do |name|
      it "rejects a blank target name (#{name.inspect}) before launching garak" do
        mod.datastore['TARGET_NAME'] = name
        mod.datastore['PROBES'] = 'probes.test.Blank'
        expect(mod).not_to receive(:execute_garak)
        expect { mod.scan_garak('/tmp') }.to raise_error(Msf::Auxiliary::Failed, /TARGET_NAME is required for SCAN/)
      end
    end

    %w[IMPORT LIST_GENERATORS LIST_PROBES].each do |action|
      it "does not require a target name for #{action}" do
        mod.datastore['ACTION'] = action
        expect { mod.options.validate(mod.datastore) }.not_to raise_error
      end
    end
  end

  describe 'probe listing' do
    before do
      mod.datastore['ACTION'] = 'LIST_PROBES'
      allow(mod).to receive(:available_plugins).with('probes').and_return(%w[dan dan.Dan_11_0 encoding.InjectBase64 test.Blank])
      allow(mod).to receive(:print_status)
    end

    it 'lists copyable probe selections without target configuration or a scan' do
      expect(mod).not_to receive(:scan_garak)
      mod.run
      expect(mod).to have_received(:print_status).with('Probe: probes.dan.Dan_11_0')
      expect(mod).to have_received(:print_status).with('Probe: probes.test.Blank')
    end

    it 'filters names case-insensitively' do
      mod.datastore['PROBE_FILTER'] = 'DAN'
      mod.run
      expect(mod).to have_received(:print_status).with('Probe: probes.dan')
      expect(mod).to have_received(:print_status).with('Probe: probes.dan.Dan_11_0')
      expect(mod).not_to have_received(:print_status).with('Probe: probes.test.Blank')
    end

    it 'treats filter metacharacters literally and reports no matches' do
      mod.datastore['PROBE_FILTER'] = '.*'
      expect(mod).to receive(:print_warning).with(/No probes matched PROBE_FILTER/)
      mod.run
    end

    it 'points to discovery and examples when probes are missing' do
      expect { mod.validate_scan }.to raise_error(Msf::Auxiliary::Failed, /ACTION LIST_PROBES.*PROBE_FILTER.*probes.test.Blank.*probes.dan.Dan_11_0/)
    end

    it 'uses the local probe CLI and parses its plain-list output' do
      allow(mod).to receive(:available_plugins).and_call_original
      allow(mod).to receive(:validate_garak_runtime).and_return('/tmp')
      expect(mod).to receive(:execute_garak) do |command, _checkout, output|
        expect(command.last).to eq('--list_probes')
        File.write(output, "garak banner\n\e[1mprobes: \e[0mdan.Dan_11_0 💤\nprobes: dan 🌟\n")
        double(success?: true)
      end
      expect(mod.available_plugins('probes')).to eq(%w[dan dan.Dan_11_0])
    end
  end
end
