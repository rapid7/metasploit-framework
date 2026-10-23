require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/bofloader'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Bofloader do
  subject(:dispatcher) { described_class.allocate }

  let(:catalog) { { 'bofs' => { 'example' => {}, 'other' => {} } } }
  let(:bofloader) { double('BOF loader', cna_catalog: catalog) }
  let(:client) { double('Meterpreter client', arch: ARCH_X64, bofloader: bofloader) }

  before do
    allow(dispatcher).to receive(:client).and_return(client)
  end

  it 'completes CNA subcommands' do
    expect(dispatcher.cmd_bof_tabs('lo', ['bof'])).to eq(['load'])
  end

  it 'completes CNA filenames for the load subcommand' do
    expect(dispatcher).to receive(:tab_complete_filenames).with('/tmp/ex', ['bof', 'load']).and_return(['/tmp/example.cna'])

    expect(dispatcher.cmd_bof_tabs('/tmp/ex', ['bof', 'load'])).to eq(['/tmp/example.cna'])
  end

  it 'completes loaded BOF names for the info and run subcommands' do
    expect(dispatcher.cmd_bof_tabs('ex', ['bof', 'info'])).to eq(['example'])
    expect(dispatcher.cmd_bof_tabs('ex', ['bof', 'run'])).to eq(['example'])
  end

  it 'returns nil when compilation fails with diagnostics' do
    compiler = Metasploit::Framework::Compiler::Mingw::X64.new
    status = instance_double(Process::Status, exitstatus: 1)
    allow(Metasploit::Framework::Compiler::Mingw::X64).to receive_messages(new: compiler, available?: true)
    allow(Open3).to receive(:capture2e).and_return(['compiler diagnostics', status])
    allow(dispatcher).to receive(:print_error)
    allow(dispatcher).to receive(:print_line).and_return('compiler diagnostics')

    expect(dispatcher.send(:compile_c, '/tmp/example.c')).to be_nil
  end

  it 'returns false when a BOF has a malformed symbol table' do
    malformed_bof = [0x8664, 0, 0, 0, 0, 0, 0].pack('vvVVVvv')
    allow(dispatcher).to receive(:print_error)

    expect(dispatcher.send(:execute_bof_data, malformed_bof, args_format: nil, args: nil, entry: 'go')).to be(false)
    expect(dispatcher).to have_received(:print_error).with(/Unable to parse the BOF: COFF symbol table is missing/)
  end
end
