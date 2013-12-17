shared_examples_for 'Msf::Ui::Console::CommandDispatcher' do
  it_should_behave_like 'Rex::Ui::Text::DispatcherShell::CommandDispatcher' do
    let(:shell) do
      command_dispatcher
    end
  end
end