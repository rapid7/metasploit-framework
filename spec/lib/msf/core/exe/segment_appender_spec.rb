require 'spec_helper'
require 'msf/core/exe/segment_appender'

RSpec.describe Msf::Exe::SegmentAppender do

  let(:opts) do
    option_hash = {
        :template => File.join(File.dirname(__FILE__), "..", "..", "..", "..", "..", "data", "templates", "template_x86_windows.exe"),
        :payload  => "\xd9\xeb\x9b\xd9\x74\x24",
        :arch     => :x86
    }
  end
  subject(:injector) { Msf::Exe::SegmentInjector.new(opts) }

  it { is_expected.to respond_to :payload }
  it { is_expected.to respond_to :template }
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :processor }
  it { is_expected.to respond_to :buffer_register }

  it 'should return the correct processor for the arch' do
    expect(injector.processor.class).to eq Metasm::Ia32
    injector.arch = :x64
    expect(injector.processor.class).to eq Metasm::X86_64
  end

  context '#create_thread_stub' do
    it 'should use edx as a default buffer register' do
      expect(injector.buffer_register).to eq 'edx'
    end

    context 'when given a non-default buffer register' do
      let(:opts) do
        option_hash = {
            :template => File.join(File.dirname(__FILE__), "..", "..", "..", "..", "..", "data", "templates", "template_x86_windows.exe"),
            :payload  => "\xd9\xeb\x9b\xd9\x74\x24",
            :arch     => :x86,
            :buffer_register => 'eax'
        }
      end
      it 'should use the correct buffer register' do
        expect(injector.buffer_register).to eq 'eax'
      end
    end
  end

  describe '#generate_pe' do
    it 'should return a string' do
      expect(injector.generate_pe.kind_of?(String)).to eq true
    end

    it 'should produce a valid PE exe' do
      expect {Metasm::PE.decode(injector.generate_pe) }.to_not raise_exception
    end

    context 'the generated exe' do
      let(:exe) { Metasm::PE.decode(injector.generate_pe) }
      it 'should be the propper arch' do
        expect(exe.bitsize).to eq 32
      end

      it 'should have 5 sections' do
        expect(exe.sections.count).to eq 5
      end

      it 'should have all the right original section names' do
        s_names = []
        exe.sections.collect {|s| s_names << s.name}
        expect(s_names[0,4]).to eq [".text", ".rdata", ".data", ".rsrc"]
      end

      it 'should have the last section set to RWX' do
        expect(exe.sections.last.characteristics).to eq ["CONTAINS_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]
      end

      it 'should have an entrypoint that points to the last section' do
        expect(exe.optheader.entrypoint).to eq exe.sections.last.virtaddr
      end
    end
  end
end

