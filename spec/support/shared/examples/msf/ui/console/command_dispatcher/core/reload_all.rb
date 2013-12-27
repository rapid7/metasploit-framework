shared_examples_for 'Msf::Ui::Console::CommandDispatcher::Core::ReloadAll' do
  it { should be_a Msf::Ui::Console::CommandDispatcher::Core::ReloadAll }

  context 'CONSTANTS' do
    context 'PROGRESS_BAR_FORMAT' do
      subject(:progress_bar_format) do
        described_class::PROGRESS_BAR_FORMAT
      end

      it 'should contains title' do
        progress_bar_format.should include('%t')
      end

      it 'should include count out of total' do
        progress_bar_format.should include('%c/%C')
      end

      it 'should include progress bar with percentage' do
        progress_bar_format.should include('|%w>%i|')
      end
    end
  end

  context '#cmd_reload_all' do
    include_context 'output'

    subject(:cmd_reload_all) do
      command_dispatcher.cmd_reload_all(*arguments)
    end

    context 'with arguments' do
      let(:arguments) do
        ['garbage']
      end

      it 'should show help' do
        command_dispatcher.should_receive(:cmd_reload_all_help)

        quietly
      end
    end

    context 'without arguments' do
      let(:arguments) do
        []
      end

      it 'should prefetch the cache with changed: true and a ruby ProgressBar factory' do
        framework.modules.cache.should_receive(:prefetch) do |options|
          options[:changed].should be_true
          progress_bar_factory = options[:progress_bar_factory]
          progress_bar_factory.should respond_to(:call)

          progress_bar = progress_bar_factory.call

          progress_bar.should be_a ProgressBar::Base
          progress_bar.instance_variable_get(:@format_string).should == described_class::PROGRESS_BAR_FORMAT
          progress_bar.send(:output).should == command_dispatcher
        end

        quietly
      end

      it 'should show cmd_banner to display the module counts after the prefetch completes' do
        framework.modules.cache.should_receive(:prefetch).ordered
        command_dispatcher.should_receive(:cmd_banner).ordered

        quietly
      end
    end
  end

  context '#cmd_reload_all_help' do
    subject(:cmd_reload_all_help) do
      command_dispatcher.cmd_reload_all_help
    end

    it 'should have loadpath as a see also reference' do
      stdout = capture(:stdout) {
        cmd_reload_all_help
      }

      stdout.should include('See also: loadpath')
    end
  end

  context '#cmd_reload_all_progress_bar_factory' do
    subject(:cmd_reload_all_progress_bar_factory) do
      command_dispatcher.cmd_reload_all_progress_bar_factory
    end

    it { should be_a ProgressBar::Base }

    context '#format' do
      let(:format) do
        cmd_reload_all_progress_bar_factory.instance_variable_get(:@format_string)
      end

      it 'should be PROGRESS_BAR_FORMAT' do
        format.should == described_class::PROGRESS_BAR_FORMAT
      end
    end

    context '#output' do
      let(:output) do
        cmd_reload_all_progress_bar_factory.send(:output)
      end

      it 'should be this command dispatcher' do
        output.should == command_dispatcher
      end
    end

    context 'called twice' do
      let(:second) do
        command_dispatcher.cmd_reload_all_progress_bar_factory
      end

      it 'should create a new ProgressBar' do
        cmd_reload_all_progress_bar_factory.should_not == second
      end
    end
  end

  context '#commands' do
    subject(:commands) do
      command_dispatcher.commands
    end

    its(['reload_all']) { should == 'Reloads all modules from all defined module paths' }
  end
end
