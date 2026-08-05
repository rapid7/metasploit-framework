# frozen_string_literal: true

require 'timeout'

RSpec.describe Msf::Sessions::WinrmPowerShell do
  let(:events) do
    double(
      'events',
      on_session_command: nil,
      on_session_interact_completed: nil,
      on_session_output: nil
    )
  end

  let(:sessions) do
    double(
      'sessions',
      deregister: nil
    )
  end

  let(:framework) do
    double(
      'framework',
      events: events,
      sessions: sessions
    )
  end

  let(:transport) do
    double(
      'transport',
      peerinfo: '192.0.2.1:5985',
      localinfo: '192.0.2.2:4444'
    )
  end

  let(:scripts) { [] }

  let(:shell) do
    double(
      'winrm powershell shell',
      transport: transport,
      close: nil
    ).tap do |mock|
      allow(mock).to receive(:run) do |script, &block|
        scripts << script
        marker_match = script.match(/;'(?<start>[A-Za-z]+)'\n(?<command>.*?)\n'(?<finish>[A-Za-z]+)';\n/m)
        if marker_match
          block.call("#{marker_match[:start]}\r\n", nil)
          block.call("marker-output\r\n", nil)
          block.call("#{marker_match[:finish]}\r\n", nil)
        else
          block.call("stdout\n", nil)
          block.call(nil, "stderr\n")
        end
      end
    end
  end

  subject(:session) { Msf::Sessions::WinrmPowerShell.new(shell) }

  before do
    session.framework = framework
  end

  describe '.type' do
    it 'returns powershell' do
      expect(described_class.type).to eq('powershell')
    end

    it 'returns a mutable string for session list serialization compatibility' do
      expect { described_class.type << ' windows' }.not_to raise_error
    end
  end

  describe '#type' do
    it 'returns powershell' do
      expect(session.type).to eq('powershell')
    end
  end

  describe '#platform' do
    it 'returns windows' do
      expect(session.platform).to eq('windows')
    end

    it 'returns a mutable string' do
      expect(session.platform).not_to be_frozen
    end
  end

  describe '#abort_foreground_supported' do
    it 'is false' do
      expect(session.abort_foreground_supported).to be(false)
    end
  end

  describe '#desc' do
    it 'returns a session-open description without the session suffix' do
      expect(session.desc).to eq('WinRM PowerShell')
    end
  end

  describe Msf::Sessions::WinrmPowerShell::WinRMPowerShellStreamAdapter do
    subject(:adapter) { described_class.new(shell, ->(_reason = '') {}) }

    it 'returns peer and local socket information from the WinRM transport' do
      expect(adapter.peerinfo).to eq('192.0.2.1:5985')
      expect(adapter.localinfo).to eq('192.0.2.2:4444')
    end

    it 'runs PowerShell input as a PSRP pipeline and buffers stdout and stderr' do
      adapter.write("Write-Output stdout\n")

      expect(adapter.get_once(-1, 1)).to eq("stdout\r\nstderr\r\n")
      expect(shell).to have_received(:run).with("Write-Output stdout\n")
    end

    it 'closes the WinRM PowerShell shell' do
      adapter.close

      expect(shell).to have_received(:close)
    end

    it 'buffers WinRM fault output and ends the session with the fault reason' do
      fault = wsman_fault('CreateShell failed.')
      queue = Queue.new
      faulting_adapter = described_class.new(shell, ->(reason = '') { queue << reason })

      allow(shell).to receive(:run).and_raise(fault)

      faulting_adapter.write("Write-Output stdout\n")

      expect(Timeout.timeout(1) { queue.pop }).to eq('CreateShell failed.')
      expect(faulting_adapter.get_once(-1, 1)).to eq('CreateShell failed.')
    end
  end

  describe '#shell_ended' do
    it 'stops interaction and deregisters the session with the reason' do
      session.interacting = true

      session.shell_ended('CreateShell failed.')

      expect(session.interacting).to be(false)
      expect(events).to have_received(:on_session_interact_completed)
      expect(sessions).to have_received(:deregister).with(session, 'CreateShell failed.')
    end
  end

  describe '#shell_command' do
    it 'uses the existing PowerShell marker command handling' do
      expect(session.shell_command('Write-Output marker-output', 1)).to eq("marker-output\r\n")
      expect(scripts.last).to include('Write-Output marker-output')
    end
  end

  describe '#_suspend' do
    before do
      allow(session).to receive(:name).and_return('2')
    end

    it 'does not send Ctrl+Z to WinRM PowerShell when backgrounding is declined' do
      session.interacting = true
      allow(session).to receive(:prompt_yesno).with('Background session 2?').and_return(false)

      expect(session.rstream).not_to receive(:write)

      session.send(:_suspend)

      expect(session.interacting).to be(true)
    end

    it 'backgrounds the session when backgrounding is accepted' do
      session.interacting = true
      allow(session).to receive(:prompt_yesno).with('Background session 2?').and_return(true)

      session.send(:_suspend)

      expect(session.interacting).to be(false)
    end
  end

  describe '#process_autoruns' do
    it 'uses CommandShell autoruns without reading a PowerShell payload banner' do
      expect(session).not_to receive(:shell_read)

      session.process_autoruns({})
    end
  end

  def wsman_fault(description)
    WinRM::WinRMWSManFault.allocate.tap do |fault|
      allow(fault).to receive(:fault_description).and_return(description)
    end
  end
end
