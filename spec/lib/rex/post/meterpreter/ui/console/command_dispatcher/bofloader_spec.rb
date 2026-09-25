require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/bofloader'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Bofloader do
  subject(:dispatcher) { described_class.allocate }

  let(:catalog) { { 'bofs' => { 'example' => {}, 'other' => {} } } }
  let(:bofloader) { double('BOF loader', cna_catalog: catalog) }
  let(:client) { double('Meterpreter client', bofloader: bofloader) }

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
end
