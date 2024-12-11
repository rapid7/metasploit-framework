require 'spec_helper'

RSpec.describe Msf::Post::Linux::Process do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Linux::Process)
    mod
  end

  describe '#mem_read' do
    let(:base_address) { 0x1000 }
    let(:length) { 64 }
    let(:pid) { 1234 }
    let(:memory_content) { 'memory content' }
    let(:mock_session) { double('Session', send: nil) }

    it 'reads memory from the specified base address and length' do
      expect(subject).to receive(:session)
      expect(subject).to receive(:open).with(pid, PROCESS_READ).and_return(1)
      expect(memory).to receive(:read).with(base_address, length).and_return(memory_content)
      expect(mock_session).to receive(:type).and_return('meterpreter')

      result = subject.mem_read(base_address, length, pid: pid)
      expect(result).to eq(memory_content)
    end

    it 'uses the default pid if not specified' do
      expect(subject).to receive(:session)
      expect(subject).to receive(:open).with(0, PROCESS_READ).and_return(1)
      expect(memory).to receive(:read).with(base_address, length).and_return(memory_content)
      expect(mock_session).to receive(:type).and_return('meterpreter')

      result = subject.mem_read(base_address, length)
      expect(result).to eq(memory_content)
    end
  end
end