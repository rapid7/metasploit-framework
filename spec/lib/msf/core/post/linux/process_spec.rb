require 'spec_helper'

RSpec.describe Msf::Post::Linux::Process do
  subject do
    mod = Msf::Exploit.allocate
    mod.extend(Msf::PostMixin)
    mod.extend described_class
    mod.send(:initialize, {})
    mod
  end

  describe '#mem_read' do
    let(:base_address) { 0x1000 }
    let(:length) { 64 }
    let(:pid) { 1234 }
    let(:process) { double('Process', send: nil) }
    let(:memory) { double('Memory', send: nil) }
    let(:memory_content) { 'memory content' }

    before do
      allow(subject).to receive_message_chain('session.sys.process.open').and_return(process)
      allow(process).to receive(:memory).and_return(memory)
    end

    it 'reads memory from the specified base address and length' do
      expect(subject).to receive(:session)
      expect(memory).to receive(:read).with(base_address, length).and_return(memory_content)

      expect(subject.mem_read(base_address, length, pid: pid)).to eq(memory_content)
    end

    it 'uses the default pid if not specified' do
      expect(subject).to receive(:session)
      expect(memory).to receive(:read).with(base_address, length).and_return(memory_content)

      expect(subject.mem_read(base_address, length)).to eq(memory_content)
    end
  end
end
