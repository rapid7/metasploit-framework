shared_examples_for 'Msf::Ui::Console::CommandDispatcher::Core::Spool' do
  context '#cmd_spool' do
    subject(:cmd_spool) do
      core.cmd_spool(*arguments)
    end

    context "with 'off'" do
      let(:arguments) do
        ['off']
      end

      it 'should set the output back to a Rex::Ui::Text::Output::Stdio' do
        msf_ui_console_driver.should_receive(:init_ui).with(
            msf_ui_console_driver.input,
            an_instance_of(Rex::Ui::Text::Output::Stdio)
        )
        msf_ui_console_driver.stub(:active_module)

        cmd_spool
      end

      it 'should not change color' do
        expect {
          cmd_spool
        }.not_to change {
          msf_ui_console_driver.output.config[:color]
        }
      end
    end

    context "without 'off'" do
      let(:arguments) do
        [path]
      end

      let(:path) do
        Metasploit::Model::Spec.temporary_pathname.join('spool.log').to_path
      end

      it 'should set the output to a Rex::Ui::Text::Output::Tee' do
        msf_ui_console_driver.should_receive(:init_ui).with(
            msf_ui_console_driver.input,
            an_instance_of(Rex::Ui::Text::Output::Tee)
        )

        cmd_spool
      end

      it 'should create Rex::Ui::Text::Output::Tee with path' do
        Rex::Ui::Text::Output::Tee.should_receive(:new).with(path)

        cmd_spool
      end

      it 'should not change color' do
        msf_ui_console_driver.should_receive(:init_ui)

        expect {
          cmd_spool
        }.not_to change {
          msf_ui_console_driver.output.config[:color]
        }
      end
    end
  end

  context '#cmd_spool_help' do
    subject(:cmd_spool_help) do
      core.cmd_spool_help
    end

    it 'should include example' do
      output = capture(:stdout) {
        cmd_spool_help
      }

      output.should include '  spool /tmp/console.log'
    end
  end

  context '#commands' do
    subject(:commands) do
      core.commands
    end

    its(['spool']) { should == 'Write console output into a file as well the screen' }
  end
end
