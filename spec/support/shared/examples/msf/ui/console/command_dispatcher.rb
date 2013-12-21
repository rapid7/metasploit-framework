shared_examples_for 'Msf::Ui::Console::CommandDispatcher' do
  shared_examples_for 'delegates to driver' do |method|
    context "##{method}" do
      subject do
        command_dispatcher.send(method)
      end

      it 'delegates to #driver' do
        expected = double(method)

        expect(command_dispatcher.driver).to receive(method).and_return(expected)
        expect(subject).to eq(expected)
      end
    end
  end

  it_should_behave_like 'Rex::Ui::Text::DispatcherShell::CommandDispatcher' do
    let(:shell) do
      command_dispatcher
    end
  end

  it_should_behave_like 'delegates to driver', :active_session
  it_should_behave_like 'delegates to driver', :active_session=
  it_should_behave_like 'delegates to driver', :metasploit_instance
  it_should_behave_like 'delegates to driver', :fanged!
  it_should_behave_like 'delegates to driver', :framework
end