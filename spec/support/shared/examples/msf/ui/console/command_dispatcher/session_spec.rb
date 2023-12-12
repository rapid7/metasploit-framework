require 'spec_helper'

RSpec.shared_examples_for 'session command dispatcher' do
  include_context 'Msf::Simple::Framework'

  describe '#client' do
    subject { command_dispatcher.client }
    it { is_expected.to be(client) }
  end

  describe '#session' do
    subject { command_dispatcher.session }
    it { is_expected.to be(session) }
  end

  describe 'Core commands' do
    describe '#cmd_background' do
      before(:each) do
        allow(session).to receive(:interacting=)
      end

      it 'backgrounds the session' do
        subject.cmd_background
        expect(session).to have_received(:interacting=).with(false)
      end

      it 'is aliased to #cmd_bg' do
        expect(subject.method(:cmd_background)).to eq(subject.method(:cmd_bg))
      end
    end

    describe '#cmd_exit' do
      before(:each) do
        allow(session).to receive(:exit)
      end

      it 'shuts down the session' do
        subject.cmd_exit
        expect(session).to have_received(:exit)
      end

      it 'is aliased to #cmd_quit' do
        expect(subject.method(:cmd_exit)).to eq(subject.method(:cmd_quit))
      end
    end

    describe '#cmd_irb' do
      let(:history_manager) { double('history_manager') }
      before(:each) do
        allow(session).to receive(:framework).and_return(framework)
        allow(framework).to receive(:history_manager).and_return(history_manager)
        allow(history_manager).to receive(:with_context).and_yield
        allow(Rex::Ui::Text::IrbShell).to receive(:new).with(session).and_return(irb_shell)
        allow(irb_shell).to receive(:run)
      end
      let(:irb_shell) { instance_double(Rex::Ui::Text::IrbShell) }
      it 'runs an irb shell instance' do
        subject.cmd_irb
        expect(Rex::Ui::Text::IrbShell).to have_received(:new).with(session)
        expect(irb_shell).to have_received(:run)
      end
    end

    describe '#cmd_sessions' do
      context 'when switching to a new session' do
        before(:each) do
          allow(session).to receive(:interacting=)
          allow(session).to receive(:next_session=)
        end

        let(:new_session_id) { 2 }

        it 'backgrounds the session and switches to the new session' do
          subject.cmd_sessions(new_session_id)
          expect(session).to have_received(:interacting=).with(false)
          expect(session).to have_received(:next_session=).with(new_session_id)
        end
      end
    end

    describe '#cmd_resource' do
      context 'when there is a valid resource script' do
        let(:valid_resource_path) { 'valid/resource/path' }
        before(:each) do
          allow(File).to receive(:exist?).and_return(valid_resource_path)
          allow(session.console).to receive(:load_resource)
        end
        it 'executes the resource script' do
          subject.cmd_resource(valid_resource_path)
          expect(session.console).to have_received(:load_resource).with(valid_resource_path)
        end
      end
    end

    %i[help background sessions resource irb pry exit].each do |command|
      describe "#cmd_#{command}" do
        before(:each) do
          allow(subject).to receive("cmd_#{command}_help")
        end
        next if %i[help exit].include?(command) # These commands don't require`-h/--help`

        context 'when called with the `-h` argument' do
          it 'should call the corresponding help function' do
            subject.send("cmd_#{command}", '-h')
            expect(subject).to have_received("cmd_#{command}_help")
          end
        end

        context 'when called with the `--help` argument' do
          it 'should call the corresponding help function' do
            subject.send("cmd_#{command}", '--help')
            expect(subject).to have_received("cmd_#{command}_help")
          end
        end
      end
    end
  end
end
