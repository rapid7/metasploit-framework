shared_examples_for 'Rex::Ui::Text::DispatcherShell::CommandDispatcher' do
  shared_examples_for 'delegates to #shell' do |method|
    context "##{method}" do
      subject(method) do
        command_dispatcher.send(method)
      end

      it 'should delegate to #shell' do
        expected = double(method)
        shell.should_receive(method).and_return(expected)

        send(method).should == expected
      end
    end
  end

  it_should_behave_like 'delegates to #shell', :flush
  it_should_behave_like 'delegates to #shell', :print
  it_should_behave_like 'delegates to #shell', :print_error
  it_should_behave_like 'delegates to #shell', :print_good
  it_should_behave_like 'delegates to #shell', :print_line
  it_should_behave_like 'delegates to #shell', :print_status
  it_should_behave_like 'delegates to #shell', :print_warning
  it_should_behave_like 'delegates to #shell', :tty?
  it_should_behave_like 'delegates to #shell', :width
end