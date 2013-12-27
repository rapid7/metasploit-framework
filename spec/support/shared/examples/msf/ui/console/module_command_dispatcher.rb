shared_examples_for 'Msf::Ui::Console::ModuleCommandDispatcher' do
  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher'

  context '#commands' do
    subject(:commands) do
      command_dispatcher.commands
    end

    its(['pry']) { should == 'Open a Pry session on the current module' }
    its(['reload']) { should == 'Reload the current module from disk' }
  end
end