# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Exe::SegmentHijacker do
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

  subject(:hijacker) { described_class.new(opts) }

  it { is_expected.to respond_to :payload }
  it { is_expected.to respond_to :template }
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :processor }
  it { is_expected.to respond_to :section_name }
  it { is_expected.to respond_to :secname }
  it { is_expected.to respond_to :section_characteristics }
  it { is_expected.not_to respond_to :build_section_data }

  describe '#generate_pe' do
    it 'should return a string' do
      expect(hijacker.generate_pe.is_a?(String)).to eq true
    end

    it 'should produce a valid PE exe' do
      expect { Metasm::PE.decode(hijacker.generate_pe) }.to_not raise_exception
    end

    context 'the generated exe' do
      let(:generated_pe) { hijacker.generate_pe }
      let(:exe) { Metasm::PE.decode(generated_pe) }

      it 'should be the proper arch' do
        expect(exe.bitsize).to eq 32
      end

      it 'should have 5 sections' do
        expect(exe.sections.count).to eq 5
      end

      it 'should have all the right original section names' do
        s_names = []
        exe.sections.collect { |section| s_names << section.name }
        expect(s_names[0, 4]).to eq ['.text', '.rdata', '.data', '.reloc']
      end

      it 'should have the last section set to RWX' do
        expect(exe.sections.last.characteristics).to eq ['CONTAINS_CODE', 'MEM_EXECUTE', 'MEM_READ', 'MEM_WRITE']
      end

      it 'should have an entrypoint that points to the last section' do
        expect(exe.optheader.entrypoint).to eq exe.sections.last.virtaddr
      end

      it 'records the generated section name' do
        generated_pe

        expect(hijacker.section_name).to match(/\A\.[a-z]{4}\z/)
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

      let(:exe) { Metasm::PE.decode(hijacker.generate_pe) }

      it 'uses the configured name for the hijacker section' do
        expect(exe.sections.last.name).to eq '.hooksec'
        expect(hijacker.section_name).to eq '.hooksec'
      end
    end
  end
end
