require 'spec_helper'
require 'msf/core/exe/segment_appender'

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
RSpec.describe Msf::Exe::SegmentAppender do
=======
describe Msf::Exe::SegmentAppender do
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
describe Msf::Exe::SegmentAppender do
>>>>>>> origin/msf-complex-payloads
=======
describe Msf::Exe::SegmentAppender do
>>>>>>> origin/msf-complex-payloads
=======
describe Msf::Exe::SegmentAppender do
>>>>>>> origin/payload-generator.rb

  let(:opts) do
    option_hash = {
        :template => File.join(File.dirname(__FILE__), "..", "..", "..", "..", "..", "data", "templates", "template_x86_windows.exe"),
        :payload  => "\xd9\xeb\x9b\xd9\x74\x24",
        :arch     => :x86
    }
  end
  subject(:injector) { Msf::Exe::SegmentInjector.new(opts) }

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  it { is_expected.to respond_to :payload }
  it { is_expected.to respond_to :template }
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :processor }
  it { is_expected.to respond_to :buffer_register }

  it 'should return the correct processor for the arch' do
    expect(injector.processor.class).to eq Metasm::Ia32
    injector.arch = :x64
    expect(injector.processor.class).to eq Metasm::X86_64
=======
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
  it { should respond_to :payload }
  it { should respond_to :template }
  it { should respond_to :arch }
  it { should respond_to :processor }
  it { should respond_to :buffer_register }

  it 'should return the correct processor for the arch' do
    injector.processor.class.should == Metasm::Ia32
    injector.arch = :x64
    injector.processor.class.should == Metasm::X86_64
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
  end

  context '#create_thread_stub' do
    it 'should use edx as a default buffer register' do
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      expect(injector.buffer_register).to eq 'edx'
=======
      injector.buffer_register.should == 'edx'
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
      injector.buffer_register.should == 'edx'
>>>>>>> origin/msf-complex-payloads
=======
      injector.buffer_register.should == 'edx'
>>>>>>> origin/msf-complex-payloads
=======
      injector.buffer_register.should == 'edx'
>>>>>>> origin/payload-generator.rb
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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        expect(injector.buffer_register).to eq 'eax'
=======
        injector.buffer_register.should == 'eax'
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
        injector.buffer_register.should == 'eax'
>>>>>>> origin/msf-complex-payloads
=======
        injector.buffer_register.should == 'eax'
>>>>>>> origin/msf-complex-payloads
=======
        injector.buffer_register.should == 'eax'
>>>>>>> origin/payload-generator.rb
      end
    end
  end

  describe '#generate_pe' do
    it 'should return a string' do
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      expect(injector.generate_pe.kind_of?(String)).to eq true
=======
      injector.generate_pe.kind_of?(String).should == true
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
      injector.generate_pe.kind_of?(String).should == true
>>>>>>> origin/msf-complex-payloads
=======
      injector.generate_pe.kind_of?(String).should == true
>>>>>>> origin/msf-complex-payloads
=======
      injector.generate_pe.kind_of?(String).should == true
>>>>>>> origin/payload-generator.rb
    end

    it 'should produce a valid PE exe' do
      expect {Metasm::PE.decode(injector.generate_pe) }.to_not raise_exception
    end

    context 'the generated exe' do
      let(:exe) { Metasm::PE.decode(injector.generate_pe) }
      it 'should be the propper arch' do
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        expect(exe.bitsize).to eq 32
      end

      it 'should have 5 sections' do
        expect(exe.sections.count).to eq 5
=======
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
        exe.bitsize.should == 32
      end

      it 'should have 5 sections' do
        exe.sections.count.should == 5
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
      end

      it 'should have all the right original section names' do
        s_names = []
        exe.sections.collect {|s| s_names << s.name}
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        expect(s_names[0,4]).to eq [".text", ".rdata", ".data", ".rsrc"]
      end

      it 'should have the last section set to RWX' do
        expect(exe.sections.last.characteristics).to eq ["CONTAINS_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]
      end

      it 'should have an entrypoint that points to the last section' do
        expect(exe.optheader.entrypoint).to eq exe.sections.last.virtaddr
=======
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
        s_names[0,4].should == [".text", ".rdata", ".data", ".rsrc"]
      end

      it 'should have the last section set to RWX' do
        exe.sections.last.characteristics.should == ["CONTAINS_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]
      end

      it 'should have an entrypoint that points to the last section' do
        exe.optheader.entrypoint.should == exe.sections.last.virtaddr
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
      end
    end
  end
end

