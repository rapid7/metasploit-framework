require 'spec_helper'

RSpec.describe Msf::Exe::SegmentInjector do
  let(:template) do
    File.join(File.dirname(__FILE__), '..', '..', '..', '..', '..', 'data', 'templates', 'template_x86_windows.exe')
  end

  let(:payload) { "\xd9\xeb\x9b\xd9\x74\x24".b }

  let(:opts) do
    {
      template: template,
      payload: payload,
      arch: :x86
    }
  end

  subject(:injector) { described_class.new(opts) }

  it { is_expected.to respond_to :payload }
  it { is_expected.to respond_to :template }
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :processor }
  it { is_expected.to respond_to :buffer_register }
  it { is_expected.to respond_to :section_name }
  it { is_expected.to respond_to :secname }
  it { is_expected.to respond_to :section_characteristics }
  it { is_expected.not_to respond_to :build_section_data }
  it { is_expected.not_to respond_to :validate_buffer_register! }
  it { is_expected.not_to respond_to :create_thread_stub }
  it { is_expected.not_to respond_to :create_thread_stub_x86 }
  it { is_expected.not_to respond_to :create_thread_stub_x64 }

  it 'should return the correct processor for the arch' do
    expect(injector.processor.class).to eq Metasm::Ia32
    injector.arch = :x64
    expect(injector.processor.class).to eq Metasm::X86_64
  end

  describe '#initialize' do
    it 'should use edx as a default buffer register' do
      expect(injector.buffer_register).to eq 'edx'
    end

    context 'when given a non-default buffer register' do
      let(:opts) do
        {
          template: template,
          payload: payload,
          arch: :x86,
          buffer_register: 'eax'
        }
      end

      it 'should use the correct buffer register' do
        expect(injector.buffer_register).to eq 'eax'
      end
    end
  end

  it 'rejects section names that cannot fit in the PE section header' do
    opts[:section_name] = 'toolong1'

    expect { injector.generate_pe }.to raise_error(
      ArgumentError,
      ":section_name must fit in the 8-byte PE section name field (7 bytes when the leading '.' is omitted)"
    )
  end

  describe '#generate_pe' do
    it 'should return a string' do
      expect(injector.generate_pe.is_a?(String)).to eq true
    end

    it 'should produce a valid PE exe' do
      expect { Metasm::PE.decode(injector.generate_pe) }.to_not raise_exception
    end

    context 'the generated exe' do
      let(:generated_pe) { injector.generate_pe }
      let(:exe) { Metasm::PE.decode(generated_pe) }

      it 'should be the proper arch' do
        expect(exe.bitsize).to eq 32
      end

      it 'should have 5 sections' do
        expect(exe.sections.count).to eq 5
      end

      it 'should have all the right section names' do
        s_names = []
        exe.sections.collect { |section| s_names << section.name }
        expect(s_names).to eq ['.text', '.rdata', '.data', '.reloc', '.text']
      end

      it 'should have the last section set to RWX' do
        expect(exe.sections.last.characteristics).to eq ['CONTAINS_CODE', 'MEM_EXECUTE', 'MEM_READ', 'MEM_WRITE']
      end

      it 'should have an entrypoint that points to the last section' do
        expect(exe.optheader.entrypoint).to eq exe.sections.last.virtaddr
      end

      it 'records the generated section name' do
        generated_pe

        expect(injector.section_name).to eq '.text'
      end
    end

    context 'when given a section name' do
      let(:opts) do
        {
          template: template,
          payload: payload,
          arch: :x86,
          section_name: 'hooksec'
        }
      end

      let(:exe) { Metasm::PE.decode(injector.generate_pe) }

      it 'uses the configured name for the injected section' do
        expect(exe.sections.last.name).to eq '.hooksec'
        expect(injector.section_name).to eq '.hooksec'
      end
    end

    context 'when given section characteristics' do
      let(:opts) do
        {
          template: template,
          payload: payload,
          arch: :x86,
          section_characteristics: %w[CONTAINS_DATA MEM_READ]
        }
      end

      let(:exe) { Metasm::PE.decode(injector.generate_pe) }

      it 'uses the configured characteristics for the injected section' do
        expect(exe.sections.last.characteristics).to include('CONTAINS_DATA', 'MEM_READ')
        expect(exe.sections.last.characteristics).not_to include('MEM_EXECUTE')
      end
    end
  end
end
