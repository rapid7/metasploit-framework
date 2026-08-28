# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/meterpreter_alias_configuration'
require 'rex/post/meterpreter/ui/console/meterpreter_alias_dispatcher'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasDispatcher do
  let(:session) { instance_double(Msf::Sessions::Meterpreter) }
  let(:console) do
    console = Rex::Post::Meterpreter::Ui::Console.new(session)
    console.disable_output = true
    console
  end
  let(:registry) do
    Rex::Post::Meterpreter::Ui::Console::MeterpreterAliasConfiguration.load(
      path: ::File.join(Msf::Config.data_directory, 'meterpreter_aliases.yml')
    )
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
      allow(session).to receive_message_chain(:sys, :config, :sysinfo).and_return('Architecture' => architecture)
      expect(session).to receive(:execute_script).with(
        'exploit/linux/persistence/elf',
        'PrependExecOnce=false',
        "TARGET=#{target}",
        "PAYLOAD=#{payload_name}",
        'ELF_PATH=/usr/bin/true'
      )

      expect(dispatcher.cmd_backdoor('/usr/bin/true')).to be(true)
    end
  end

  it 'applies switch options' do
    allow(session).to receive(:platform).and_return('linux')
    allow(session).to receive_message_chain(:sys, :config, :sysinfo).and_return('Architecture' => ARCH_AARCH64)
    expect(session).to receive(:execute_script).with(
      'exploit/linux/persistence/elf',
      'PrependExecOnce=true',
      'TARGET=2',
      'PAYLOAD=linux/aarch64/meterpreter/reverse_tcp',
      'PayloadLinuxMinKernel=3.17',
      'ELF_PATH=/usr/bin/true'
    )

    expect(dispatcher.cmd_backdoor('/usr/bin/true', '-x')).to be(true)
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

    expect(dispatcher.commands).not_to include('backdoor')
    expect(dispatcher.cmd_backdoor('/usr/bin/true')).to be(false)
  end

  it 'rejects unknown switches' do
    allow(session).to receive(:platform).and_return('linux')

    expect(session).not_to receive(:execute_script)
    expect(dispatcher.cmd_backdoor('/usr/bin/true', '-z')).to be(false)
  end

  it 'reloads through the plugin callback' do
    allow(reload_callback).to receive(:call).and_return(true)

    expect(dispatcher.cmd_aliases_reload).to be(true)
  end
end
