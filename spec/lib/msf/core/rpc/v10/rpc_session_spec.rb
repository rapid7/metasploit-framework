# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Session do
  include_context 'Msf::Simple::Framework'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false
  include_context 'wait_for_expect'

  def create_mock_session(klass)
    instance_double(
      klass,
      sid: target_sid,
      type: klass.type
    )
  end

  let(:service) { Msf::RPC::Service.new(framework) }
  let(:rpc) { described_class.new(service) }
  let(:target_sid) { 1 }

  let(:sessions) do
    { target_sid => session }
  end

  before do
    allow(framework).to receive(:sessions).and_return(sessions)
  end

  let(:user_input) { Rex::Ui::Text::Input::Buffer.new }
  let(:user_output) { Rex::Ui::Text::Output::Buffer.new }

  let(:init_ui_handler) do
    proc do
      allow(session).to receive(:user_output).and_return(user_output)
      allow(session).to receive(:user_input).and_return(user_input)
    end
  end

  let(:rstream) do
    instance_double(Rex::IO::Stream)
  end

  let(:meterpreter_session) { create_mock_session(::Msf::Sessions::Meterpreter_x64_Win) }
  let(:postgresql_session) { create_mock_session(::Msf::Sessions::PostgreSQL) }
  let(:shell_session) { create_mock_session(::Msf::Sessions::CommandShell) }

  shared_examples 'interactive read' do
    let(:expected_data) { 'test response' }

    let(:user_output) do
      output = Rex::Ui::Text::Output::Buffer.new
      output.print(expected_data)
      output
    end

    context 'when UI is not initialized' do
      before do
        allow(session).to receive(:user_output).once.and_return(nil)
        allow(session).to receive(:init_ui).and_invoke(init_ui_handler)
      end

      it 'returns expected data' do
        expect(response).to eq({ 'data' => expected_data })
      end
    end

    context 'when UI is initialized' do
      before do
        allow(session).to receive(:user_output).and_return(user_output)
      end

      it 'returns expected data' do
        expect(response).to eq({ 'data' => expected_data })
      end
    end
  end

  shared_examples 'interactive write' do
    let(:test_command) { 'help' }

    context 'when UI is not initialized' do
      let(:console) do
        instance_double(Rex::Ui::Text::DispatcherShell)
      end

      before do
        allow(session).to receive(:user_output).once.and_return(nil)
        allow(session).to receive(:init_ui).and_invoke(init_ui_handler)
        allow(session).to receive(:interacting).and_return(false)
      end

      it 'returns result: success' do
        expect(response).to eq({ 'result' => 'success' })
      end
    end

    context 'when UI is initialized' do
      let(:user_input) do
        buffer = instance_double(Rex::Ui::Text::Input::Buffer)
        input = test_command + "\n"
        allow(buffer).to receive(:put).with(input).and_return(input.length)
        buffer
      end

      before do
        allow(session).to receive(:user_output).and_return(user_output)
        allow(session).to receive(:user_input).and_return(user_input)
      end

      context 'when interacting' do
        before do
          allow(session).to receive(:interacting).and_return(true)
        end

        it 'returns result: success and pushes command to user_input' do
          expect(response).to eq({ 'result' => 'success' })
          expect(user_input).to have_received(:put).with(test_command + "\n")
        end
      end

      context 'when not interacting' do
        before do
          allow(session).to receive(:interacting).and_return(false)
        end

        it 'returns result: success and pushes command to user_input' do
          expect(response).to eq({ 'result' => 'success' })
        end
      end
    end
  end

  describe '#rpc_meterpreter_read' do
    subject(:response) { rpc.rpc_meterpreter_read(target_sid) }

    context 'with meterpreter session' do
      let(:session) { meterpreter_session }

      it_behaves_like 'interactive read'
    end

    context 'with postgresql session' do
      let(:session) { postgresql_session }

      it_behaves_like 'interactive read'
    end

    context 'with shell session' do
      let(:session) { shell_session }

      it 'raises an error' do
        expect { response }.to raise_error(Msf::RPC::Exception)
      end
    end
  end

  describe '#rpc_interactive_read' do
    subject(:response) do
      rpc.rpc_interactive_read(target_sid)
    end

    context 'with postgresql session' do
      let(:session) { postgresql_session }

      it_behaves_like 'interactive read'
    end

    context 'with meterpreter session' do
      let(:session) { meterpreter_session }

      it_behaves_like 'interactive read'
    end

    context 'with shell session' do
      let(:session) { shell_session }

      it 'raises an error' do
        expect { response }.to raise_error(Msf::RPC::Exception)
      end
    end
  end

  describe '#rpc_shell_read' do
    subject(:response) { rpc.rpc_shell_read(target_sid) }

    context 'with postgresql session' do
      let(:session) { postgresql_session }

      it 'raises an error' do
        expect { response }.to raise_error(Msf::RPC::Exception)
      end
    end

    context 'with shell session' do
      let(:session) do
        session = Msf::Sessions::CommandShell.new(rstream)
        session.framework = framework
        session
      end

      let(:expected_data) { 'test response' }

      before do
        allow(rstream).to receive(:get_once).and_return(expected_data)
      end

      it "doesn't raise an error" do
        expect { response }.not_to raise_error
      end

      it 'returns expected data' do
        expect(response).to eq({ 'seq' => 0, 'data' => expected_data })
      end
    end
  end

  describe '#rpc_shell_write' do
    let(:test_command) { 'help' }

    subject(:response) { rpc.rpc_shell_write(target_sid, test_command) }

    context 'with postgresql session' do
      let(:session) { postgresql_session }

      it 'raises an error' do
        expect { response }.to raise_error(Msf::RPC::Exception)
      end
    end

    context 'with shell session' do
      let(:session) do
        session = Msf::Sessions::CommandShell.new(rstream)
        session.framework = framework
        session
      end

      before do
        allow(rstream).to receive(:write).with(test_command).and_return(test_command.length)
      end

      it "doesn't raise an error" do
        expect { response }.not_to raise_error
      end

      it 'returns write_count data' do
        expect(response).to eq({ 'write_count' => test_command.length.to_s })
      end
    end
  end

  describe '#rpc_interactive_write' do
    let(:test_command) { 'help' }

    subject(:response) { rpc.rpc_interactive_write(target_sid, test_command) }

    context 'with shell session' do
      let(:session) { shell_session }

      it 'raises error' do
        expect { response }.to raise_error(Msf::RPC::Exception)
      end
    end

    context 'with meterpreter session' do
      let(:session) { meterpreter_session }

      it_behaves_like 'interactive write'
    end

    context 'with postgresql session' do
      let(:session) { postgresql_session }

      it_behaves_like 'interactive write'
    end
  end

  describe '#rpc_meterpreter_write' do
    let(:test_command) { 'help' }

    subject(:response) { rpc.rpc_meterpreter_write(target_sid, test_command) }

    context 'with shell session' do
      let(:session) { shell_session }

      it 'raises error' do
        expect { response }.to raise_error(Msf::RPC::Exception)
      end
    end

    context 'with meterpreter session' do
      let(:session) { meterpreter_session }

      it_behaves_like 'interactive write'
    end

    context 'with postgresql session' do
      let(:session) { postgresql_session }

      it_behaves_like 'interactive write'
    end
  end
end
