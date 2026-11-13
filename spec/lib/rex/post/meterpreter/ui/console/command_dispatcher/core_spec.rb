# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Core do
  let(:session) { instance_double(Msf::Sessions::Meterpreter) }
  # A meterpreter session *is* a client but for the smb session it *has* a (ruby smb) client
  let(:client) { session }
  let(:console) do
    console = Rex::Post::Meterpreter::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  describe '#parse_work_days' do
    it 'parses hexadecimal masks in base 16' do
      expect(command_dispatcher.parse_work_days('0x3e')).to eq(62)
    end

    it 'accepts an uppercase hexadecimal prefix and digits' do
      expect(command_dispatcher.parse_work_days('0X3E')).to eq(62)
    end

    it 'parses decimal masks in base 10' do
      expect(command_dispatcher.parse_work_days('62')).to eq(62)
    end

    it 'keeps decimal masks with leading zeros in base 10' do
      expect(command_dispatcher.parse_work_days('062')).to eq(62)
    end
  end

  describe '#async_config_validation_error' do
    let(:session) { Msf::Sessions::Meterpreter.allocate }
    let(:config) { client.async_config }

    it 'accepts valid target settings and console job limits' do
      expect(command_dispatcher.async_config_validation_error(config)).to be_nil
    end

    it 'returns the shared target validation error' do
      config[:poll_interval] = 9

      expect(command_dispatcher.async_config_validation_error(config)).to eq('Poll interval must be between 10 and 86400 seconds.')
    end

    it 'rejects a lease TTL below 30 seconds' do
      config[:lease_ttl] = 29

      expect(command_dispatcher.async_config_validation_error(config)).to eq('Lease TTL must be between 30 and 3600 seconds.')
    end

    it 'rejects a lease TTL above one hour' do
      config[:lease_ttl] = 3601

      expect(command_dispatcher.async_config_validation_error(config)).to eq('Lease TTL must be between 30 and 3600 seconds.')
    end

    it 'rejects a job timeout shorter than the lease TTL' do
      config[:job_timeout] = config[:lease_ttl] - 1

      expect(command_dispatcher.async_config_validation_error(config)).to eq('Job timeout must be at least the lease TTL.')
    end
  end

  describe '#async_subcmd_run' do
    let(:rid) { '0123456789abcdef0123456789abcdef' }
    let(:store) { instance_double(Rex::Post::Meterpreter::AsyncResultStore, complete: nil) }
    let(:async_shell) { instance_double(Rex::Post::Meterpreter::Ui::Console, run_single: nil) }
    let(:saved_user_input) { Object.new }
    let(:saved_user_output) { Object.new }

    before do
      allow(client).to receive(:async_mode_enabled?).and_return(true)
      allow(client).to receive(:async_store).and_return(store)
      allow(Rex::Text).to receive(:rand_text_hex).with(32).and_return(rid)
      allow(store).to receive(:enqueue_work).and_yield(rid)
      allow(client).to receive(:async_shell).with(console).and_return(async_shell)
      allow(client).to receive(:with_async_lease).and_yield
      allow(client).to receive(:async_config).and_return(job_timeout: 30)
      allow(client).to receive(:async_seconds_until_next_window).and_return(0)
      allow(client).to receive(:target_time_sample_age).and_return(0)
      allow(client).to receive(:console=)
      allow(client).to receive(:user_input).and_return(saved_user_input)
      allow(client).to receive(:user_output).and_return(saved_user_output)
      allow(client).to receive(:user_input=)
      allow(client).to receive(:user_output=)
      allow(client).to receive(:init_ui)
    end

    it 'enqueues the command with a 32-character hexadecimal request ID' do
      command_dispatcher.async_subcmd_run(['sysinfo'])

      expect(store).to have_received(:enqueue_work).with(rid, 'sysinfo')
    end

    it 'restores session handles without reinitializing the console UI' do
      command_dispatcher.async_subcmd_run(['sysinfo'])

      expect(client).to have_received(:user_input=).with(saved_user_input)
      expect(client).to have_received(:user_output=).with(saved_user_output)
      expect(client).not_to have_received(:init_ui)
    end

    context 'when both saved session handles are nil' do
      let(:saved_user_input) { nil }
      let(:saved_user_output) { nil }

      it 'restores both nil handles' do
        command_dispatcher.async_subcmd_run(['sysinfo'])

        expect(client).to have_received(:user_input=).with(nil)
        expect(client).to have_received(:user_output=).with(nil)
      end
    end

    it 'restores the session handles when the async command fails' do
      error = Rex::TimeoutError.new('Async command timed out')
      allow(async_shell).to receive(:run_single).and_raise(error)

      expect { command_dispatcher.async_subcmd_run(['sysinfo']) }.to raise_error(error)

      expect(client).to have_received(:user_input=).with(saved_user_input)
      expect(client).to have_received(:user_output=).with(saved_user_output)
      expect(client).not_to have_received(:init_ui)
    end
  end

  it_behaves_like 'session command dispatcher'
end
