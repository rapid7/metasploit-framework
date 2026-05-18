# frozen_string_literal: true

require 'rspec'

RSpec.describe 'WinRM Login Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/winrm/winrm_login'
    )
  end

  let(:credential) do
    double(
      'credential',
      public: username,
      private: password
    )
  end

  let(:conn) { double('winrm connection') }
  let(:cmd_shell) { double('cmd shell', owner: owner, connection_opts: { user: username }) }
  let(:ps_shell) { double('powershell shell') }
  let(:cmd_session) { double('cmd session') }
  let(:ps_session) { double('powershell session') }
  let(:command_id) { 'command-id' }
  let(:owner) { 'EIGHTEEN\\adam.scott' }
  let(:password) { 'iloveyou1' }
  let(:rhost) { '192.0.2.10' }
  let(:rport) { 5985 }
  let(:endpoint) { 'http://192.0.2.10:5985/wsman' }
  let(:username) { 'adam.scott' }

  describe 'SessionType option' do
    it 'defaults to cmd' do
      expect(mod.datastore['SessionType']).to eq('cmd')
    end

    it 'accepts cmd, powershell, and auto' do
      expect(mod.options['SessionType'].enums).to eq(%w[cmd powershell auto])
    end
  end

  describe '#create_winrm_session' do
    before do
      allow(mod).to receive(:wlog)
      allow(mod).to receive(:elog)
    end

    context 'when SessionType is cmd' do
      before do
        mod.datastore['SessionType'] = 'cmd'
      end

      it 'creates the existing stdin cmd shell session' do
        expect(conn).to receive(:shell).with(:stdin, {}).and_return(cmd_shell)
        expect(conn).not_to receive(:shell).with(:powershell)
        expect(cmd_shell).to receive(:send_command).with('cmd.exe').and_return(command_id)
        expect(Msf::Sessions::WinrmCommandShell).to receive(:new).with(cmd_shell, command_id).and_return(cmd_session)
        expect(cmd_session).to receive(:platform=).with('windows')
        expect(mod).to receive(:start_session).with(
          mod,
          "WinRM #{username}:#{password} (#{owner})",
          hash_including('USERNAME' => username, 'PASSWORD' => password),
          false,
          nil,
          cmd_session
        ).and_return(cmd_session)

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to eq(cmd_session)
      end

      it 'prints a cmd CreateShell access denied warning with a SessionType hint' do
        fault = access_denied_fault
        expect(conn).to receive(:shell).with(:stdin, {}).and_raise(fault)
        expect(conn).not_to receive(:shell).with(:powershell)
        expect(mod).to receive(:print_warning).with(
          "#{rhost}:#{rport} - Credentials were correct, but WinRM cmd shell CreateShell was denied for user: #{username}. Try setting SessionType to powershell or auto."
        )

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to be_nil
      end
    end

    context 'when SessionType is powershell' do
      before do
        mod.datastore['SessionType'] = 'powershell'
      end

      it 'creates a WinRM PowerShell session' do
        expect(conn).to receive(:shell).with(:powershell).and_return(ps_shell)
        expect(conn).not_to receive(:shell).with(:stdin, {})
        expect(mod).to receive(:powershell_owner).with(ps_shell).and_return(owner)
        expect(Msf::Sessions::WinrmPowerShell).to receive(:new).with(ps_shell).and_return(ps_session)
        expect(mod).to receive(:start_session).with(
          mod,
          "WinRM PowerShell #{username}:#{password} (#{owner})",
          hash_including('USERNAME' => username, 'PASSWORD' => password),
          false,
          nil,
          ps_session
        ).and_return(ps_session)

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to eq(ps_session)
      end
    end

    context 'when SessionType is auto' do
      before do
        mod.datastore['SessionType'] = 'auto'
      end

      it 'does not try PowerShell when the cmd shell succeeds' do
        expect(conn).to receive(:shell).with(:stdin, {}).and_return(cmd_shell)
        expect(conn).not_to receive(:shell).with(:powershell)
        expect(cmd_shell).to receive(:send_command).with('cmd.exe').and_return(command_id)
        expect(Msf::Sessions::WinrmCommandShell).to receive(:new).with(cmd_shell, command_id).and_return(cmd_session)
        expect(cmd_session).to receive(:platform=).with('windows')
        expect(mod).to receive(:start_session).and_return(cmd_session)

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to eq(cmd_session)
      end

      it 'falls back to PowerShell on cmd CreateShell access denied' do
        fault = access_denied_fault
        expect(conn).to receive(:shell).with(:stdin, {}).and_raise(fault)
        expect(mod).to receive(:print_warning).with(
          "#{rhost}:#{rport} - Credentials were correct, but WinRM cmd shell CreateShell was denied for user: #{username}"
        )
        expect(mod).to receive(:print_status).with(
          "#{rhost}:#{rport} - Falling back to a WinRM PowerShell session because cmd shell CreateShell was denied"
        )
        expect(conn).to receive(:shell).with(:powershell).and_return(ps_shell)
        expect(mod).to receive(:powershell_owner).with(ps_shell).and_return(owner)
        expect(Msf::Sessions::WinrmPowerShell).to receive(:new).with(ps_shell).and_return(ps_session)
        expect(mod).to receive(:start_session).and_return(ps_session)

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to eq(ps_session)
      end

      it 'falls back to PowerShell on cmd.exe CreateShell access denied' do
        fault = access_denied_fault
        expect(conn).to receive(:shell).with(:stdin, {}).and_return(cmd_shell)
        expect(cmd_shell).to receive(:send_command).with('cmd.exe').and_raise(fault)
        expect(mod).to receive(:print_warning).with(
          "#{rhost}:#{rport} - Credentials were correct, but WinRM cmd shell CreateShell was denied for user: #{username}"
        )
        expect(mod).to receive(:print_status).with(
          "#{rhost}:#{rport} - Falling back to a WinRM PowerShell session because cmd shell CreateShell was denied"
        )
        expect(conn).to receive(:shell).with(:powershell).and_return(ps_shell)
        expect(mod).to receive(:powershell_owner).with(ps_shell).and_return(owner)
        expect(Msf::Sessions::WinrmPowerShell).to receive(:new).with(ps_shell).and_return(ps_session)
        expect(mod).to receive(:start_session).and_return(ps_session)

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to eq(ps_session)
      end

      it 'does not fall back to PowerShell when session registration raises a WSMan fault' do
        fault = access_denied_fault
        expect(conn).to receive(:shell).with(:stdin, {}).and_return(cmd_shell)
        expect(conn).not_to receive(:shell).with(:powershell)
        expect(cmd_shell).to receive(:send_command).with('cmd.exe').and_return(command_id)
        expect(Msf::Sessions::WinrmCommandShell).to receive(:new).with(cmd_shell, command_id).and_return(cmd_session)
        expect(cmd_session).to receive(:platform=).with('windows')
        expect(mod).to receive(:start_session).and_raise(fault)

        expect do
          mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)
        end.to raise_error(WinRM::WinRMWSManFault)
      end

      it 'does not fall back to PowerShell on other cmd shell failures' do
        fault = wsman_fault('1234', 'Unexpected WSMan fault.')
        expect(conn).to receive(:shell).with(:stdin, {}).and_raise(fault)
        expect(conn).not_to receive(:shell).with(:powershell)
        expect(mod).to receive(:print_error).with("#{rhost}:#{rport} - Unexpected WSMan fault.")

        expect(mod.send(:create_winrm_session, conn, credential, rhost, rport, endpoint)).to be_nil
      end
    end
  end

  def access_denied_fault
    wsman_fault(
      ::WindowsError::Win32::ERROR_ACCESS_DENIED.value.to_s,
      'Access is denied.',
      'CreateShell failed: 5: Access is denied.'
    )
  end

  def wsman_fault(code, description, full_message = description)
    WinRM::WinRMWSManFault.allocate.tap do |fault|
      allow(fault).to receive(:fault_code).and_return(code)
      allow(fault).to receive(:fault_description).and_return(description)
      allow(fault).to receive(:full_message).and_return(full_message)
    end
  end
end
