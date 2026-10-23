require_relative 'spec_helper'

RSpec.describe Msf::Plugin::Garak::ConsoleCommandDispatcher do
  subject(:dispatcher) { described_class.new(driver) }

  let(:framework) { Msf::Simple::Framework.create('DisableDatabase' => true, 'DeferModuleLoads' => true) }
  let(:output) { Rex::Ui::Text::Output::Buffer.new }
  let(:driver) { double('console', framework: framework, input: nil, output: output, on_command_proc: nil) }

  before do
    allow(driver).to receive(:on_command_proc=)
    allow(driver).to receive(:print_status)
  end

  it 'accepts case insensitive defaults and restores runner defaults when unset' do
    dispatcher.cmd_garak_set('generations', '3')
    expect(dispatcher.send(:build_runner, 'scan').datastore['GENERATIONS']).to eq(3)
    dispatcher.cmd_garak_unset('GENERATIONS')
    expect(dispatcher.send(:build_runner, 'scan').datastore['GENERATIONS']).to eq(1)
  end

  it 'runs the selected action with literal arguments and leaves defaults unchanged' do
    dispatcher.cmd_garak_set('TARGET_NAME', 'default')
    expect(Msf::Simple::Auxiliary).to receive(:run_simple) do |runner, options|
      expect(runner.datastore['TARGET_NAME']).to eq('default')
      expect(options).to include('Action' => 'SCAN', 'RunAsJob' => false)
      expect(options['Options']).to eq('TARGET_NAME' => 'model with spaces;$(false)=value', 'VERBOSE' => 'true')
    end
    dispatcher.cmd_garak_scan('target_name=model with spaces;$(false)=value', 'verbose=true')
    expect(dispatcher.send(:build_runner, 'scan').datastore['TARGET_NAME']).to eq('default')
  end

  it 'rejects unknown options and action overrides' do
    expect(Msf::Simple::Auxiliary).not_to receive(:run_simple)
    expect(dispatcher).to receive(:print_error).with(/Unknown Garak option/).exactly(3).times
    dispatcher.cmd_garak_scan('TYPO=value')
    dispatcher.cmd_garak_scan('ACTION=IMPORT')
    dispatcher.cmd_garak_scan('API_KEY=value')
  end

  it 'accepts a REST API key for an individual scan' do
    expect(Msf::Simple::Auxiliary).to receive(:run_simple).with(anything, hash_including('Options' => { 'REST_API_KEY' => 'test-key' }))
    dispatcher.cmd_garak_scan('REST_API_KEY=test-key')
    expect(dispatcher.send(:build_runner, 'scan').datastore['REST_API_KEY']).to be_nil
  end

  it 'rejects malformed arguments before execution' do
    expect(Msf::Simple::Auxiliary).not_to receive(:run_simple)
    expect(dispatcher).to receive(:print_error).with(/Expected OPTION=VALUE/)
    dispatcher.cmd_garak_import('/path/to/report')
  end

  it 'routes import and listing commands without requiring scan options' do
    expect(Msf::Simple::Auxiliary).to receive(:run_simple).with(anything, hash_including('Action' => 'IMPORT'))
    expect(Msf::Simple::Auxiliary).to receive(:run_simple).with(anything, hash_including('Action' => 'LIST_GENERATORS'))
    expect(Msf::Simple::Auxiliary).to receive(:run_simple).with(anything, hash_including('Action' => 'LIST_PROBES'))
    dispatcher.cmd_garak_import('REPORT_FILE=/tmp/report.jsonl')
    dispatcher.cmd_garak_list_generators
    dispatcher.cmd_garak_list_probes
  end

  it 'keeps runner state and dispatcher defaults independent' do
    dispatcher.cmd_garak_set('RHOSTS', '192.0.2.1')
    first = dispatcher.send(:build_runner, 'scan')
    first.datastore['RHOSTS'] = '192.0.2.2'
    expect(dispatcher.send(:build_runner, 'scan').datastore['RHOSTS']).to eq('192.0.2.1')
    expect(described_class.new(driver).send(:build_runner, 'scan').datastore['RHOSTS']).to be_nil
  end

  it 'renders the framework option tables' do
    expect(dispatcher).to receive(:print_line).with(a_string_including('TARGET_NAME'))
    allow(dispatcher).to receive(:print_line)
    dispatcher.cmd_garak_options
  end
end

RSpec.describe Msf::Plugin::Garak do
  it 'registers and removes the console dispatcher' do
    framework = Msf::Simple::Framework.create('DisableDatabase' => true, 'DeferModuleLoads' => true)
    driver = double('console')
    expect(driver).to receive(:append_dispatcher).with(described_class::ConsoleCommandDispatcher)
    plugin = described_class.new(framework, 'ConsoleDriver' => driver)
    expect(driver).to receive(:remove_dispatcher).with('Garak')
    plugin.cleanup
  end
end
