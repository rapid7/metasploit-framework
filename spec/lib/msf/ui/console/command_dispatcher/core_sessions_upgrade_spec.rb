# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Core do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:core) do
    described_class.new(driver)
  end

  describe '#cmd_sessions -u (session upgrade routing)' do
    let(:sess_id) { 1 }
    let(:session) { double('session') }
    let(:mock_input) { double('input') }
    let(:mock_output) { double('output') }
    let(:mock_module) { double('post_module') }

    before(:each) do
      allow(driver).to receive(:input).and_return(mock_input)
      allow(driver).to receive(:output).and_return(mock_output)
      allow(driver).to receive(:active_session=)
      allow(core).to receive(:verify_session).with(sess_id).and_return(session)
    end

    context 'when session type is smb' do
      before(:each) do
        allow(session).to receive(:type).and_return('smb')
      end

      context 'when the upgrade module is available' do
        before(:each) do
          allow(framework.modules).to receive(:create).with('post/windows/manage/smb_to_meterpreter').and_return(mock_module)
          allow(mock_module).to receive(:run_simple)
          allow(session).to receive(:exploit_datastore).and_return(nil)
        end

        it 'routes to the smb_to_meterpreter module' do
          expect(framework.modules).to receive(:create).with('post/windows/manage/smb_to_meterpreter').and_return(mock_module)
          expect(mock_module).to receive(:run_simple).with(
            hash_including(
              'LocalInput' => mock_input,
              'LocalOutput' => mock_output,
              'Options' => hash_including('SESSION' => sess_id.to_s)
            )
          )

          core.cmd_sessions('-u', sess_id.to_s)
        end

        it 'passes session datastore values to the upgrade module' do
          exploit_datastore = {
            'LHOST' => '192.0.2.1',
            'LPORT' => 4444,
            'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp',
            'TARGET_ARCH' => 'x64'
          }
          allow(session).to receive(:exploit_datastore).and_return(exploit_datastore)

          expect(mock_module).to receive(:run_simple).with(
            hash_including(
              'Options' => {
                'SESSION' => sess_id.to_s,
                'LHOST' => '192.0.2.1',
                'LPORT' => 4444,
                'TARGET_ARCH' => 'x64'
              }
            )
          )

          core.cmd_sessions('-u', sess_id.to_s)
        end
      end

      context 'when the upgrade module is not available' do
        before(:each) do
          allow(framework.modules).to receive(:create).with('post/windows/manage/smb_to_meterpreter').and_return(nil)
        end

        it 'prints an error and does not attempt to run' do
          expect(core).to receive(:print_error).with('Failed to create post/windows/manage/smb_to_meterpreter module.')

          core.cmd_sessions('-u', sess_id.to_s)
        end
      end
    end

    context 'when session type is shell' do
      before(:each) do
        allow(session).to receive(:type).and_return('shell')
        allow(session).to receive(:respond_to?).with(:response_timeout).and_return(false)
        allow(session).to receive(:init_ui)
        allow(session).to receive(:execute_script).with('post/multi/manage/shell_to_meterpreter')
        allow(session).to receive(:reset_ui)
      end

      it 'routes to shell_to_meterpreter via execute_script' do
        expect(session).to receive(:execute_script).with('post/multi/manage/shell_to_meterpreter')
        expect(framework.modules).not_to receive(:create).with('post/windows/manage/smb_to_meterpreter')

        core.cmd_sessions('-u', sess_id.to_s)
      end
    end

    context 'when session type is meterpreter' do
      before(:each) do
        allow(session).to receive(:type).and_return('meterpreter')
        allow(session).to receive(:respond_to?).with(:response_timeout).and_return(false)
        allow(session).to receive(:init_ui)
        allow(session).to receive(:execute_script).with('post/multi/manage/shell_to_meterpreter')
        allow(session).to receive(:reset_ui)
      end

      it 'routes to shell_to_meterpreter via execute_script' do
        expect(session).to receive(:execute_script).with('post/multi/manage/shell_to_meterpreter')
        expect(framework.modules).not_to receive(:create).with('post/windows/manage/smb_to_meterpreter')

        core.cmd_sessions('-u', sess_id.to_s)
      end
    end
  end
end
