require 'spec_helper'

RSpec.describe 'Garak integration' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/garak/garak_integration')
  end

  before do
    mod.datastore['VERBOSE'] = true
    # Option validation requires an existing path, even when garak execution is mocked.
    mod.datastore['GARAK_PATH'] = Dir.tmpdir
    allow(mod).to receive(:db).and_return(false)
    allow(mod).to receive(:print_warning)
  end

  describe '#report_database' do
    let(:records) do
      [
        { 'entry_type' => 'start_run setup', 'plugins.target_type' => 'test.Repeat', 'plugins.target_name' => 'test-model' },
        { 'entry_type' => 'init', 'run' => 'run-123', 'garak_version' => '0.17.1', 'start_time' => '2026-09-29T15:54:25' },
        { 'entry_type' => 'attempt', 'status' => 1, 'uuid' => 'attempt-123' },
        { 'entry_type' => 'attempt', 'status' => 2, 'uuid' => 'attempt-123', 'outputs' => [{ 'text' => 'DAN Mode enabled' }] },
        { 'entry_type' => 'completion', 'run' => 'run-123', 'end_time' => '2026-09-29T15:55:34' }
      ]
    end
    let(:evaluations) { [{ 'probe' => 'dan.Dan_11_0', 'detector' => 'dan.DAN', 'passed' => 0, 'failed' => 1, 'total_evaluated' => 1 }] }

    before do
      allow(mod).to receive(:db).and_return(true)
      allow(mod).to receive(:report_note)
    end

    it 'stores model identity, evaluations and only completed attempts as workspace notes' do
      expect(mod).not_to receive(:report_host)
      expect(mod).not_to receive(:report_service)
      expect(mod).not_to receive(:report_vuln)
      mod.report_database(records, evaluations, 'report-hash')
      expect(mod).to have_received(:report_note).with(hash_including(type: 'garak.run', update: :unique_data, data: hash_including('run_id' => 'run-123', 'target_name' => 'test-model', 'complete' => true)))
      expect(mod).to have_received(:report_note).with(hash_including(type: 'garak.evaluation', data: hash_including('evaluation' => evaluations.first)))
      expect(mod).to have_received(:report_note).with(hash_including(type: 'garak.attempt', data: hash_including('attempt' => records[3]))).once
      expect(mod).to have_received(:report_note).exactly(3).times
    end

    it 'associates records with an explicitly provided host and service' do
      mod.datastore['DB_HOST'] = '192.0.2.1'
      mod.datastore['DB_PORT'] = 8080
      mod.datastore['DB_SERVICE'] = 'test'
      expect(mod).to receive(:report_host).with(host: '192.0.2.1')
      expect(mod).to receive(:report_service).with(host: '192.0.2.1', port: 8080, proto: 'tcp', name: 'test')
      mod.report_database(records, evaluations, 'report-hash')
      expect(mod).to have_received(:report_note).with(hash_including(host: '192.0.2.1', port: 8080, proto: 'tcp', sname: 'test')).exactly(3).times
    end

    it 'keeps incomplete runs identifiable and uses the report hash when no run ID exists' do
      mod.report_database([], evaluations, 'report-hash')
      expect(mod).to have_received(:report_note).with(hash_including(type: 'garak.run', data: hash_including('run_id' => 'report-hash', 'complete' => false)))
    end

    it 'does not create database entries without validated evaluations' do
      mod.report_database(records, [], 'report-hash')
      expect(mod).not_to have_received(:report_note)
    end

    it 'warns when there is no database connection' do
      allow(mod).to receive(:db).and_return(false)
      expect(mod).to receive(:print_warning).with('Database is not connected; garak results are available in loot only')
      mod.report_database(records, evaluations, 'report-hash')
      expect(mod).not_to have_received(:report_note)
    end
  end

  describe '#garak_command' do
    {
      'ollama' => ['ollama', 'OllamaGeneratorChat', 'host'],
      'ollama.OllamaGeneratorChat' => ['ollama', 'OllamaGeneratorChat', 'host'],
      'ollama.OllamaGenerator' => ['ollama', 'OllamaGenerator', 'host'],
      'rest' => ['rest', 'RestGenerator', 'uri'],
      'rest.RestGenerator' => ['rest', 'RestGenerator', 'uri'],
      'openai.OpenAICompatible' => ['openai', 'OpenAICompatible', 'uri']
    }.each do |adapter, (plugin, klass, key)|
      it "maps the endpoint for #{adapter} while retaining provider configuration" do
        mod.datastore['TARGET_TYPE'] = adapter
        mod.datastore['CONFIG_FILE'] = '/tmp/provider.yaml'
        command = mod.garak_command('/tmp/report', endpoint: 'https://[2001:db8::1]:8443/api/generate')
        expect(JSON.parse(command[command.index('--generator_options') + 1])).to eq(plugin => { klass => { key => 'https://[2001:db8::1]:8443/api/generate' } })
        expect(command[command.index('--config') + 1]).to eq('/tmp/provider.yaml')
      end
    end

    it 'passes arbitrary adapters through without injecting endpoint settings' do
      mod.datastore['TARGET_TYPE'] = 'custom.Provider'
      mod.datastore['TARGET_NAME'] = 'custom-model'
      mod.datastore['CONFIG_FILE'] = '/tmp/provider.yaml'
      command = mod.garak_command('/tmp/report')
      expect(command[command.index('--target_type') + 1]).to eq('custom.Provider')
      expect(command[command.index('--target_name') + 1]).to eq('custom-model')
      expect(command[command.index('--config') + 1]).to eq('/tmp/provider.yaml')
      expect(command).not_to include('--generator_options')
    end

    it 'omits the model argument when none is configured' do
      expect(mod.garak_command('/tmp/report')).not_to include('--target_name')
    end

    it 'keeps model names and paths as literal arguments' do
      mod.datastore['TARGET_NAME'] = 'model;$(touch /tmp/should-not-exist)'
      mod.datastore['CONFIG_FILE'] = '/tmp/config with spaces.yaml'
      command = mod.garak_command('/tmp/report with spaces')
      expect(command[command.index('--target_name') + 1]).to eq(mod.datastore['TARGET_NAME'])
      expect(command[command.index('--config') + 1]).to eq('/tmp/config with spaces.yaml')
      expect(command[command.index('--report_prefix') + 1]).to eq('/tmp/report with spaces')
    end
  end

  describe '#run' do
    it 'rejects an unmapped adapter when remote hosts are supplied' do
      mod.datastore['TARGET_TYPE'] = 'custom.Provider'
      mod.datastore['RHOSTS'] = '192.0.2.1'
      expect(mod).not_to receive(:scan_garak)
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /no endpoint mapping.*Unset RHOSTS/)
    end

    it 'uses one generic scan path without provider-specific requirements' do
      mod.datastore['TARGET_TYPE'] = 'custom.Provider'
      expect(mod).to receive(:scan_garak).with(File.expand_path(mod.datastore['GARAK_PATH']))
      mod.run
    end

    it 'allows a local generator with an explicit model name' do
      mod.datastore['TARGET_TYPE'] = 'test.Blank'
      mod.datastore['TARGET_NAME'] = 'test-model'
      mod.datastore['PROBES'] = 'probes.test.Blank'
      expect(mod).to receive(:scan_garak).with(File.expand_path(mod.datastore['GARAK_PATH']))
      mod.run
    end

    it 'imports an existing report without scan options or a subprocess' do
      mod.datastore['ACTION'] = 'IMPORT'
      Dir.mktmpdir do |directory|
        path = File.join(directory, 'report.jsonl')
        File.write(path, "{\"entry_type\":\"completion\"}\n")
        mod.datastore['REPORT_FILE'] = path
        expect { mod.options.validate(mod.datastore) }.not_to raise_error
        expect(mod).not_to receive(:execute_garak)
        expect(mod).to receive(:import_report).with(File.binread(path))
        mod.run
      end
    end

    it 'requires a report path for IMPORT' do
      mod.datastore['ACTION'] = 'IMPORT'
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /REPORT_FILE is required/)
    end

    it 'includes installed generator names in the error for a missing TARGET_TYPE' do
      mod.datastore['ACTION'] = 'SCAN'
      allow(mod).to receive(:available_generators).and_return(%w[test.Repeat test.Blank])
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Available TARGET_TYPE values: test.Repeat, test.Blank/)
    end

    it 'lists generators without scan or import settings' do
      mod.datastore['ACTION'] = 'LIST_GENERATORS'
      allow(mod).to receive(:available_generators).and_return(['test.Repeat'])
      expect(mod).to receive(:print_status).with('Generator: test.Repeat')
      expect(mod).to receive(:print_status).with(/Set ACTION SCAN/)
      expect(mod).not_to receive(:scan_garak)
      mod.run
    end
  end

  describe '#run_host' do
    it 'uses the scanned address for endpoint and database attribution without mutating configuration' do
      mod.datastore['RPORT'] = 8443
      mod.datastore['SSL'] = true
      mod.datastore['TARGETURI'] = '/api/generate'
      mod.datastore['DB_HOST'] = '192.0.2.99'
      mod.datastore['DB_PORT'] = 9999
      %w[192.0.2.1 192.0.2.2].each do |host|
        expect(mod).to receive(:scan_garak).with(anything, endpoint: "https://#{host}:8443/api/generate", association: { host: host, port: 8443, proto: 'tcp', sname: 'https' })
        mod.run_host(host)
      end
      expect(mod.datastore['DB_HOST']).to eq('192.0.2.99')
      expect(mod.datastore['DB_PORT']).to eq(9999)
    end

    it 'formats IPv6 endpoints correctly' do
      expect(mod).to receive(:scan_garak).with(anything, endpoint: 'http://[2001:db8::1]:80/', association: hash_including(host: '2001:db8::1', sname: 'http'))
      mod.run_host('2001:db8::1')
    end
  end

  describe '#generator_names' do
    it 'extracts CLI adapter names and aliases while ignoring banners, colors and activation markers' do
      output = "garak version banner\n\e[1mgenerators: \e[0mtest 🌟\ngenerators: test.Blank 💤\ngenerators: test.Repeat\ngenerators: test.Blank\n"
      expect(mod.generator_names(output)).to eq(%w[test test.Blank test.Repeat])
    end
  end

  describe '#available_generators' do
    before do
      allow(mod).to receive(:validate_garak_runtime).and_return('/tmp')
    end

    it 'uses the local CLI without verbose table formatting or scan arguments' do
      expect(mod).to receive(:execute_garak) do |command, checkout, output|
        expect(command).to eq(['python3', '-u', '-m', 'garak', '--list_generators'])
        expect(checkout).to eq('/tmp')
        File.write(output, "generators: test.Blank\n")
        double(success?: true)
      end
      expect(mod.available_generators).to eq(['test.Blank'])
    end

    it 'reports listing timeouts' do
      allow(mod).to receive(:execute_garak).and_return(nil)
      expect { mod.available_generators }.to raise_error(Msf::Auxiliary::Failed, /exceeded RunTimeout/)
    end

    it 'reports missing Python dependencies' do
      allow(mod).to receive(:execute_garak).and_return(double(success?: false))
      expect { mod.available_generators }.to raise_error(Msf::Auxiliary::Failed, /check PYTHON, GARAK_PATH/)
    end

    it 'rejects a successful command with an unrecognized listing format' do
      allow(mod).to receive(:execute_garak).and_return(double(success?: true))
      expect { mod.available_generators }.to raise_error(Msf::Auxiliary::Failed, /no recognizable generators/)
    end
  end

  describe '#summarize_report' do
    let(:evaluation) { { entry_type: 'eval', probe: 'test.Blank', detector: 'always.Pass', passed: 2, total_evaluated: 3 } }

    it 'reports failures as detections and recognizes completion' do
      expect(mod).to receive(:print_warning).with('Probe test.Blank / always.Pass: 1 failed, 2 passed, 3 evaluated')
      expect(mod).not_to receive(:print_warning).with(/incomplete/)
      expect(mod).to receive(:print_status).with('Imported 1 garak evaluations')
      mod.summarize_report([evaluation, { entry_type: 'completion' }].map(&:to_json).join("\n"))
    end

    it 'supports legacy totals without retaining counts between runs' do
      evaluation[:total] = evaluation.delete(:total_evaluated)
      expect(mod).to receive(:print_status).with('Imported 1 garak evaluations').twice
      2.times { mod.summarize_report(evaluation.to_json) }
    end

    it 'preserves valid results when another line is malformed or has an invalid shape' do
      expect(mod).to receive(:print_warning).with('Skipping invalid JSON at report line 1')
      expect(mod).to receive(:print_warning).with('Skipping invalid evaluation at report line 3')
      expect(mod).to receive(:print_warning).with('Garak report is incomplete (no completion record)')
      expect(mod).to receive(:print_warning).with(/1 failed/)
      expect(mod).to receive(:print_status).with('Imported 1 garak evaluations')
      mod.summarize_report("broken\n#{evaluation.to_json}\n#{evaluation.merge(passed: -1).to_json}\n[]\n")
    end

    it 'does not interpret zero evaluated responses as a successful assessment' do
      expect(mod).to receive(:print_status).with(/0 failed, 0 passed, 0 evaluated/)
      expect(mod).to receive(:print_status).with('Imported 1 garak evaluations')
      mod.summarize_report(evaluation.merge(passed: 0, total_evaluated: 0).to_json)
    end
  end

  describe '#execute_garak' do
    it 'returns a nonzero process status for a failed subprocess' do
      Dir.mktmpdir do |directory|
        status = mod.execute_garak([RbConfig.ruby, '-e', 'exit 7'], directory, File.join(directory, 'output'))
        expect(status.exitstatus).to eq(7)
      end
    end

    it 'terminates and reaps a subprocess when its runtime expires' do
      mod.datastore['RunTimeout'] = 1
      Dir.mktmpdir do |directory|
        output = File.join(directory, 'output')
        expect(mod.execute_garak([RbConfig.ruby, '-e', '$stdout.sync = true; puts Process.pid; sleep 30'], directory, output)).to be_nil
        pid = File.read(output).to_i
        expect(pid).to be_positive
        expect { Process.kill(0, pid) }.to raise_error(Errno::ESRCH)
      end
    end
  end
end
