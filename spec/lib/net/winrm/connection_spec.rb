# frozen_string_literal: true

require 'net/winrm/connection'

RSpec.describe Net::MsfWinRM::RexWinRMConnection::ShellFactory do
  subject(:factory) { described_class.new(connection_opts, transport, logger) }

  let(:connection_opts) do
    {
      endpoint: 'http://192.0.2.10:5985/wsman',
      retry_delay: 1,
      retry_limit: 0
    }
  end

  let(:logger) { double('logger') }
  let(:transport) { double('transport') }

  describe '#create_shell' do
    it 'creates the Rex stdin shell for stdin shell requests' do
      expect(factory.create_shell(:stdin)).to be_a(Net::MsfWinRM::StdinShell)
    end

    it 'creates the Rex-safe PowerShell shell for PowerShell requests' do
      expect(factory.create_shell(:powershell)).to be_a(Net::MsfWinRM::PowerShell)
    end

    it 'delegates other shell types to the upstream factory' do
      expect(factory.create_shell(:cmd)).to be_a(WinRM::Shells::Cmd)
    end

    it 'does not register ObjectSpace finalizers for PowerShell shells' do
      shell = factory.create_shell(:powershell)

      expect(ObjectSpace).not_to receive(:define_finalizer)
      expect(ObjectSpace).not_to receive(:undefine_finalizer)

      shell.add_finalizer
      shell.remove_finalizer
    end
  end
end
