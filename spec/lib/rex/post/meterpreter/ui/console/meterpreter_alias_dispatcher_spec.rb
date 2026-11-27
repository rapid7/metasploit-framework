# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/meterpreter_alias_dispatcher'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasDispatcher do
  def stub_architecture(architecture)
    sys_config = double('Meterpreter sys config', sysinfo: { 'Architecture' => architecture })
    allow(session).to receive(:sys).and_return(double('Meterpreter sys extension', config: sys_config))
  end

  # Meterpreter extension aliases such as `sys` are added dynamically at runtime.
  let(:session) { double('Meterpreter client') }
  let(:console) do
    console = Rex::Post::Meterpreter::Ui::Console.new(session)
    console.disable_output = true
    console
  end
  let(:registry) do
    {
      'path' => 'meterpreter_aliases.yml',
      'aliases' => {
        'test_alias' => {
          'description' => 'Run a test module',
          'platforms' => ['linux'],
          'module' => 'post/linux/gather/enum_system',
          'positional' => [
            {
              'option' => 'TARGET_PATH',
              'required' => true
            }
          ],
          'defaults' => {
            'VERBOSE' => false
          },
          'switches' => {
            '-x' => {
              'description' => 'Enable execution',
              'options' => {
                'VERBOSE' => true,
                'EXECUTE' => true
              }
            }
          },
          'architecture_options' => {
            'source' => 'sysinfo',
            'values' => {
              ARCH_X64 => {
                'TARGET' => 0,
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              },
              ARCH_X86 => {
                'TARGET' => 1,
                'PAYLOAD' => 'linux/x86/meterpreter/reverse_tcp'
              },
              ARCH_AARCH64 => {
                'TARGET' => 2,
                'PAYLOAD' => 'linux/aarch64/meterpreter/reverse_tcp'
              }
            }
          }
        },
        'execute-assembly' => {
          'description' => 'Execute a .NET assembly in memory',
          'platforms' => ['windows'],
          'module' => 'post/windows/manage/execute_dotnet_assembly',
          'positional' => [
            {
              'option' => 'DOTNET_EXE',
              'required' => true
            },
            {
              'option' => 'ARGUMENTS',
              'required' => false
            }
          ],
          'defaults' => {},
          'switches' => {},
          'architecture_options' => nil
        },
        'enum_persistence' => {
          'description' => 'Suggest persistence modules for the current session',
          'platforms' => %w[linux osx windows],
          'module' => 'post/multi/recon/persistence_suggester',
          'positional' => [],
          'defaults' => {},
          'switches' => {},
          'architecture_options' => nil
        }
      }
    }
  end
  let(:reload_callback) { instance_double(Proc) }

  before do
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return(1)
  end

  subject(:dispatcher) { described_class.new(console, registry: registry, reload_callback: reload_callback) }

  {
    ARCH_X64 => ['0', 'linux/x64/meterpreter/reverse_tcp'],
    ARCH_X86 => ['1', 'linux/x86/meterpreter/reverse_tcp'],
    ARCH_AARCH64 => ['2', 'linux/aarch64/meterpreter/reverse_tcp']
  }.each do |architecture, (target, payload_name)|
    it "runs architecture options for #{architecture}" do
      allow(session).to receive(:platform).and_return('linux')
      stub_architecture(architecture)
      expect(session).to receive(:execute_script).with(
        'post/linux/gather/enum_system',
        'VERBOSE=false',
        "TARGET=#{target}",
        "PAYLOAD=#{payload_name}",
        'TARGET_PATH=/usr/bin/true'
      )

      expect(dispatcher.cmd_test_alias('/usr/bin/true')).to be(true)
    end
  end

  it 'applies switch options' do
    allow(session).to receive(:platform).and_return('linux')
    stub_architecture(ARCH_AARCH64)
    expect(session).to receive(:execute_script).with(
      'post/linux/gather/enum_system',
      'VERBOSE=true',
      'TARGET=2',
      'PAYLOAD=linux/aarch64/meterpreter/reverse_tcp',
      'EXECUTE=true',
      'TARGET_PATH=/usr/bin/true'
    )

    expect(dispatcher.cmd_test_alias('/usr/bin/true', '-x')).to be(true)
  end

  it 'runs execute-assembly with an optional argument string' do
    allow(session).to receive(:platform).and_return('windows')
    expect(session).to receive(:execute_script).with(
      'post/windows/manage/execute_dotnet_assembly',
      'DOTNET_EXE=/tmp/Rubeus.exe',
      'ARGUMENTS=triage /nowrap'
    )

    expect(dispatcher.public_send('cmd_execute-assembly', '/tmp/Rubeus.exe', 'triage /nowrap')).to be(true)
  end

  it 'runs the persistence suggester alias' do
    allow(session).to receive(:platform).and_return('linux')
    expect(session).to receive(:execute_script).with('post/multi/recon/persistence_suggester')

    expect(dispatcher.cmd_enum_persistence).to be(true)
  end

  it 'hides aliases that do not support the session platform' do
    allow(session).to receive(:platform).and_return('windows')

    expect(dispatcher.commands).not_to include('test_alias')
    expect(dispatcher.cmd_test_alias('/usr/bin/true')).to be(false)
  end

  it 'rejects unknown switches' do
    allow(session).to receive(:platform).and_return('linux')

    expect(session).not_to receive(:execute_script)
    expect(dispatcher.cmd_test_alias('/usr/bin/true', '-z')).to be(false)
  end

  it 'reloads through the plugin callback' do
    expect(reload_callback).to receive(:call).and_return(true)

    expect(dispatcher.cmd_aliases_reload).to be(true)
  end
end
