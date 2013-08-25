require 'spec_helper'
require 'msf/core/exe/segment_injector'

describe Msf::Exe::SegmentInjector do

  let(:opts) do
    option_hash = {
        :template => File.join(File.dirname(__FILE__), "..", "..", "..", "..", "..", "data", "templates", "template_x86_windows.exe"),
        :payload  => "\xd9\xeb\x9b\xd9\x74\x24",
        :arch     => :x86
    }
  end
  subject(:injector) { Msf::Exe::SegmentInjector.new(opts) }

  it { should respond_to :payload }
  it { should respond_to :template }
  it { should respond_to :arch }
  it { should respond_to :processor }

  it 'should return the correct processor for the arch' do
    injector.processor.class.should == Metasm::Ia32
    injector.arch = :x64
    injector.processor.class.should == Metasm::X86_64
  end

  context '#payload_as_asm' do
    it 'should return the payload as declare byte instructions' do
      injector.payload_as_asm.should == "db 0xd9\ndb 0xeb\ndb 0x9b\ndb 0xd9\ndb 0x74\ndb 0x24\n"
    end
  end

  describe '#generate_pe' do
    it 'should return a string' do
      injector.generate_pe.kind_of?(String).should == true
    end

    it 'should produce a valid PE exe' do
      expect {Metasm::PE.decode(injector.generate_pe) }.to_not raise_exception
    end

    context 'the generated exe' do
      let(:exe) { Metasm::PE.decode(injector.generate_pe) }
      it 'should be the propper arch' do
        exe.bitsize.should == 32
      end

      it 'should have 5 sections' do
        exe.sections.count.should == 5
      end

      it 'should have all the right section names' do
        s_names = []
        exe.sections.collect {|s| s_names << s.name}
        s_names.should == [".text", ".rdata", ".data", ".rsrc", ".text"]
      end

      it 'should have the last section set to RWX' do
        exe.sections.last.characteristics.should == ["CONTAINS_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]
      end

      it 'should have an entrypoint that points to the last section' do
        exe.optheader.entrypoint.should == exe.sections.last.virtaddr
      end
    end
  end
end

