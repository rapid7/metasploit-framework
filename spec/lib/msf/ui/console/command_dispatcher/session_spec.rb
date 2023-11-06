RSpec.shared_examples_for 'session command dispatcher' do
  describe '#client' do
    subject { command_dispatcher.client }
    it { is_expected.to be(client) }
  end

  describe 'Core commands' do
    describe '#cmd_background' do
      it 'backgrounds the session' do
        subject.cmd_background
        expect(client.interacting).to be(false)
      end

      it 'is aliased to #cmd_bg' do
        expect(subject.method(:cmd_background)).to eq(subject.method(:cmd_bg))
      end
    end

    describe '#cmd_exit' do
      it 'shuts down the session' do
        expect(client).to receive(:exit)
        subject.cmd_exit
      end

      it 'is aliased to #cmd_quit' do
        expect(subject.method(:cmd_exit)).to eq(subject.method(:cmd_quit))
      end
    end

    describe '#cmd_irb' do
      let(:framework) { double('framework') }
      let(:history_manager) { double('history_manager') }
      before(:each) do
        allow(client).to receive(:framework).and_return(framework)
        allow(framework).to receive(:history_manager).and_return(history_manager)
        allow(history_manager).to receive(:with_context).and_yield
      end
      let(:irb_shell) { instance_double(Rex::Ui::Text::IrbShell) }
      it 'runs an irb shell instance' do
        expect(Rex::Ui::Text::IrbShell).to receive(:new).with(client).and_return(irb_shell)
        expect(irb_shell).to receive(:run)
        subject.cmd_irb
      end
    end

    describe '#cmd_sessions' do
      context 'when switching to a new session' do
        let(:new_session_id) { 2 }

        it 'backgrounds the session and switches to the new session' do
          subject.cmd_sessions(new_session_id)
          expect(client.interacting).to be(false)
          expect(client.next_session).to eq(new_session_id)
        end
      end
    end

    describe '#cmd_resource' do
      context 'there is a valid resource script' do
        let(:valid_resource_path) { 'valid/resource/path' }
        before(:each) do
          allow(File).to receive(:exist?).and_return(valid_resource_path)
        end
        it 'executes the resource script' do
          expect(client.console).to receive(:load_resource).with(valid_resource_path)
          subject.cmd_resource(valid_resource_path)
        end
      end
    end

    %i[help background sessions resource irb pry exit].each do |command|
      describe "#cmd_#{command}" do
        next if %i[help exit].include?(command) # These commands don't require`-h/--help`

        context 'when called with the `-h` argument' do
          it 'should call the corresponding help function' do
            expect(subject).to receive("cmd_#{command}_help")
            subject.send("cmd_#{command}", '-h')
          end
        end

        context 'when called with the `--help` argument' do
          it 'should call the corresponding help function' do
            expect(subject).to receive("cmd_#{command}_help")
            subject.send("cmd_#{command}", '--help')
          end
        end
      end
    end
  end
end
