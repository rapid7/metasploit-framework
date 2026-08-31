# frozen_string_literal: true

require 'spec_helper'

# rubocop:disable Metrics/BlockLength
RSpec.describe Msf::Post::SessionUpgrade do
  subject do
    context_described_class = described_class

    klass = Class.new(Msf::Post) do
      include context_described_class
    end

    klass.new
  end

  describe 'option registration' do
    describe 'LHOST' do
      it 'is registered as an OptAddressLocal' do
        expect(subject.options['LHOST']).to be_a(Msf::OptAddressLocal)
      end

      it 'is not required' do
        expect(subject.options['LHOST'].required?).to be(false)
      end
    end

    describe 'LPORT' do
      it 'is registered as an OptInt' do
        expect(subject.options['LPORT']).to be_a(Msf::OptInt)
      end

      it 'has a default value of 4444' do
        expect(subject.options['LPORT'].default).to eq(4444)
      end

      it 'is required' do
        expect(subject.options['LPORT'].required?).to be(true)
      end
    end

    describe 'HANDLER' do
      it 'is registered as an OptBool' do
        expect(subject.options['HANDLER']).to be_a(Msf::OptBool)
      end

      it 'has a default value of true' do
        expect(subject.options['HANDLER'].default).to eq(true)
      end

      it 'is required' do
        expect(subject.options['HANDLER'].required?).to be(true)
      end
    end

    describe 'HANDLE_TIMEOUT' do
      it 'is registered as an OptInt' do
        expect(subject.options['HANDLE_TIMEOUT']).to be_a(Msf::OptInt)
      end

      it 'has a default value of 30' do
        expect(subject.options['HANDLE_TIMEOUT'].default).to eq(30)
      end

      it 'is required' do
        expect(subject.options['HANDLE_TIMEOUT'].required?).to be(true)
      end

      it 'is an advanced option' do
        expect(subject.options['HANDLE_TIMEOUT'].advanced?).to be(true)
      end
    end
  end

  describe '#resolve_lhost' do
    let(:mock_session) { double('session', tunnel_local: '') }
    let(:framework_datastore) { {} }

    before do
      allow(subject).to receive(:session).and_return(mock_session)
      allow(subject.framework).to receive(:datastore).and_return(framework_datastore)
      allow(subject).to receive(:print_error)
    end

    context 'when module datastore LHOST is set' do
      before do
        subject.datastore['LHOST'] = '10.0.0.1'
      end

      it 'returns the module datastore LHOST' do
        expect(subject.send(:resolve_lhost)).to eq('10.0.0.1')
      end
    end

    context 'when module LHOST is blank but framework LHOST is set' do
      let(:framework_datastore) { { 'LHOST' => '10.0.0.2' } }

      before do
        subject.datastore['LHOST'] = ''
      end

      it 'returns the framework datastore LHOST' do
        expect(subject.send(:resolve_lhost)).to eq('10.0.0.2')
      end
    end

    context 'when both datastores are blank but session tunnel_local has a host' do
      let(:mock_session) { double('session', tunnel_local: '192.168.1.5:4444') }

      before do
        subject.datastore['LHOST'] = ''
      end

      it 'returns the host extracted from tunnel_local' do
        expect(subject.send(:resolve_lhost)).to eq('192.168.1.5')
      end
    end

    context 'when both datastores are blank and tunnel_local is "Local Pipe"' do
      let(:mock_session) { double('session', tunnel_local: 'Local Pipe') }

      before do
        subject.datastore['LHOST'] = ''
      end

      it 'returns nil' do
        expect(subject.send(:resolve_lhost)).to be_nil
      end

      it 'prints an error' do
        subject.send(:resolve_lhost)
        expect(subject).to have_received(:print_error).with(/Cannot determine LHOST/)
      end
    end

    context 'when both datastores are blank and tunnel_local host portion is blank' do
      let(:mock_session) { double('session', tunnel_local: ':4444') }

      before do
        subject.datastore['LHOST'] = ''
      end

      it 'returns nil' do
        expect(subject.send(:resolve_lhost)).to be_nil
      end

      it 'prints an error' do
        subject.send(:resolve_lhost)
        expect(subject).to have_received(:print_error).with(/Cannot determine LHOST/)
      end
    end

    context 'when all sources are blank' do
      let(:mock_session) { double('session', tunnel_local: '') }

      before do
        subject.datastore['LHOST'] = ''
      end

      it 'returns nil' do
        expect(subject.send(:resolve_lhost)).to be_nil
      end

      it 'prints an error' do
        subject.send(:resolve_lhost)
        expect(subject).to have_received(:print_error).with(/Unable to determine LHOST/)
      end
    end
  end

  describe '#start_upgrade_handler' do
    let(:handler_mod) do
      double(
        'handler_module',
        datastore: {},
        job_id: 42
      )
    end
    let(:mock_exploits) { double('exploits') }
    let(:mock_jobs) { double('jobs', :[] => double('job')) }

    before do
      allow(subject).to receive(:print_status)
      allow(subject).to receive(:print_error)
      allow(subject).to receive(:user_input).and_return(nil)
      allow(subject).to receive(:user_output).and_return(nil)
      allow(Rex::ThreadSafe).to receive(:sleep)

      subject.datastore['HANDLER'] = true
      subject.datastore['PAYLOAD'] = 'windows/meterpreter/reverse_tcp'
      subject.datastore['LPORT'] = 4433

      allow(subject).to receive(:framework).and_return(
        double('framework', exploits: mock_exploits, jobs: mock_jobs)
      )
      allow(mock_exploits).to receive(:create).with('multi/handler').and_return(handler_mod)
      allow(handler_mod).to receive(:exploit_simple)
      allow(subject).to receive(:check_for_listener).and_return(false)
    end

    it 'raises failure when port is already in use' do
      allow(subject).to receive(:check_for_listener).and_return(true)
      expect {
        subject.send(:start_upgrade_handler, '192.0.2.1')
      }.to raise_error(Msf::Post::Failed, /already in use/)
    end

    it 'raises failure when handler job disappears after start' do
      allow(mock_jobs).to receive(:[]).and_return(nil)
      expect {
        subject.send(:start_upgrade_handler, '192.0.2.1')
      }.to raise_error(Msf::Post::Failed, /failed to start/)
    end

    it 'configures the handler with correct payload, LHOST, and LPORT' do
      subject.send(:start_upgrade_handler, '192.0.2.1')
      expect(handler_mod.datastore['PAYLOAD']).to eq('windows/meterpreter/reverse_tcp')
      expect(handler_mod.datastore['LHOST']).to eq('192.0.2.1')
      expect(handler_mod.datastore['LPORT']).to eq(4433)
    end

    it 'returns the job ID string on success' do
      result = subject.send(:start_upgrade_handler, '192.0.2.1')
      expect(result).to eq('42')
    end

    it 'stores the job ID in @upgrade_handler_job_id' do
      subject.send(:start_upgrade_handler, '192.0.2.1')
      expect(subject.instance_variable_get(:@upgrade_handler_job_id)).to eq('42')
    end
  end

  describe '#cleanup_upgrade_handler' do
    let(:mock_jobs) { double('jobs') }

    before do
      allow(subject).to receive(:print_status)
      allow(subject).to receive(:print_error)
      allow(subject).to receive(:framework).and_return(
        double('framework', jobs: mock_jobs)
      )
    end

    it 'stops the job when @upgrade_handler_job_id is set and job exists' do
      allow(mock_jobs).to receive(:[]).with('42').and_return(double('job'))
      allow(mock_jobs).to receive(:stop_job).with('42')
      subject.instance_variable_set(:@upgrade_handler_job_id, '42')

      subject.send(:cleanup_upgrade_handler)
      expect(mock_jobs).to have_received(:stop_job).with('42')
    end

    it 'clears @upgrade_handler_job_id after stopping' do
      allow(mock_jobs).to receive(:[]).with('42').and_return(double('job'))
      allow(mock_jobs).to receive(:stop_job).with('42')
      subject.instance_variable_set(:@upgrade_handler_job_id, '42')

      subject.send(:cleanup_upgrade_handler)
      expect(subject.instance_variable_get(:@upgrade_handler_job_id)).to be_nil
    end

    it 'does nothing when @upgrade_handler_job_id is nil' do
      subject.instance_variable_set(:@upgrade_handler_job_id, nil)
      expect { subject.send(:cleanup_upgrade_handler) }.not_to raise_error
    end

    it 'handles case where job ID is set but job no longer exists' do
      allow(mock_jobs).to receive(:[]).with('42').and_return(nil)
      subject.instance_variable_set(:@upgrade_handler_job_id, '42')

      expect { subject.send(:cleanup_upgrade_handler) }.not_to raise_error
      expect(subject.instance_variable_get(:@upgrade_handler_job_id)).to be_nil
    end
  end

  describe '#generate_upgrade_payload' do
    let(:mock_payloads) { double('payloads') }

    before do
      allow(subject).to receive(:print_error)
      allow(subject).to receive(:framework).and_return(
        double('framework', payloads: mock_payloads)
      )
    end

    context 'when a valid payload name is provided' do
      let(:payload_obj) { double('payload', generate_simple: "\x90\x90\xcc") }

      before do
        allow(mock_payloads).to receive(:create).with('windows/meterpreter/reverse_tcp').and_return(payload_obj)
      end

      it 'returns raw payload bytes' do
        result = subject.generate_upgrade_payload('192.0.2.1', 4433, 'windows/meterpreter/reverse_tcp')
        expect(result).to eq("\x90\x90\xcc")
      end

      it 'calls generate_simple with LHOST and LPORT' do
        expect(payload_obj).to receive(:generate_simple).with('OptionStr' => 'LHOST=192.0.2.1 LPORT=4433')
        subject.generate_upgrade_payload('192.0.2.1', 4433, 'windows/meterpreter/reverse_tcp')
      end
    end

    context 'when an invalid payload name is provided' do
      before do
        allow(mock_payloads).to receive(:create).with('invalid/payload').and_return(nil)
      end

      it 'returns nil' do
        result = subject.generate_upgrade_payload('192.0.2.1', 4433, 'invalid/payload')
        expect(result).to be_nil
      end

      it 'prints an error message' do
        subject.generate_upgrade_payload('192.0.2.1', 4433, 'invalid/payload')
        expect(subject).to have_received(:print_error).with(/Invalid payload/)
      end
    end

    context 'when payload does not respond to generate_simple' do
      let(:payload_obj) { double('payload') }

      before do
        allow(mock_payloads).to receive(:create).with('windows/meterpreter/reverse_tcp').and_return(payload_obj)
      end

      it 'returns nil' do
        result = subject.generate_upgrade_payload('192.0.2.1', 4433, 'windows/meterpreter/reverse_tcp')
        expect(result).to be_nil
      end

      it 'prints an error message' do
        subject.generate_upgrade_payload('192.0.2.1', 4433, 'windows/meterpreter/reverse_tcp')
        expect(subject).to have_received(:print_error).with(/does not support generate_simple/)
      end
    end
  end

  describe '#wait_for_upgrade_session' do
    let(:mock_sessions) { double('sessions') }

    before do
      allow(subject).to receive(:print_status)
      allow(subject).to receive(:print_good)
      allow(subject).to receive(:print_error)
      allow(Rex::ThreadSafe).to receive(:sleep)

      subject.datastore['HANDLE_TIMEOUT'] = 2

      allow(subject).to receive(:framework).and_return(
        double('framework', sessions: mock_sessions)
      )
    end

    context 'when a new session appears within timeout' do
      before do
        allow(mock_sessions).to receive(:keys).and_return([1, 2], [1, 2, 3])
      end

      it 'returns true' do
        result = subject.send(:wait_for_upgrade_session, Set[1, 2])
        expect(result).to be(true)
      end

      it 'prints a success message' do
        subject.send(:wait_for_upgrade_session, Set[1, 2])
        expect(subject).to have_received(:print_good).with(/session opened/)
      end
    end

    context 'when no new session appears within timeout' do
      before do
        allow(mock_sessions).to receive(:keys).and_return([1, 2])
      end

      it 'returns false' do
        result = subject.send(:wait_for_upgrade_session, Set[1, 2])
        expect(result).to be(false)
      end

      it 'prints an error message' do
        subject.send(:wait_for_upgrade_session, Set[1, 2])
        expect(subject).to have_received(:print_error).with(/No session received/)
      end
    end

    context 'when pre-existing sessions are present' do
      before do
        # Sessions 1 and 2 already exist; no new ones appear
        allow(mock_sessions).to receive(:keys).and_return([1, 2])
      end

      it 'ignores pre-existing sessions and returns false on timeout' do
        result = subject.send(:wait_for_upgrade_session, Set[1, 2])
        expect(result).to be(false)
      end
    end
  end

  describe '#execute_upgrade' do
    it 'raises NotImplementedError when not implemented by consuming module' do
      expect do
        subject.execute_upgrade('192.0.2.1')
      end.to raise_error(NotImplementedError, /Consuming modules must implement execute_upgrade/)
    end
  end
end
# rubocop:enable Metrics/BlockLength
