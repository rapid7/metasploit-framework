require 'spec_helper'

RSpec.describe Msf::Exe::SegmentAppender do
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

  subject(:appender) { described_class.new(opts) }

  it { is_expected.to respond_to :payload }
  it { is_expected.to respond_to :template }
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :processor }
  it { is_expected.to respond_to :section_name }
  it { is_expected.to respond_to :secname }
  it { is_expected.to respond_to :section_characteristics }
  it { is_expected.not_to respond_to :build_section_data }

  it 'aliases legacy secname accessors to section_name' do
    appender.secname = 'legacy'

    expect(appender.section_name).to eq('legacy')
    expect(appender.secname).to eq('legacy')
  end

  it 'should return the correct processor for the arch' do
    expect(appender.processor.class).to eq Metasm::Ia32
    appender.arch = :x64
    expect(appender.processor.class).to eq Metasm::X86_64
  end

  it 'rejects section names that cannot fit in the PE section header' do
    opts[:section_name] = 'toolong1'

    expect { appender.generate_pe }.to raise_error(
      ArgumentError,
      ":section_name must fit in the 8-byte PE section name field (7 bytes when the leading '.' is omitted)"
    )
  end

  describe '#generate_pe' do
    it 'should return a string' do
      expect(appender.generate_pe.is_a?(String)).to eq true
    end

    it 'should produce a valid PE exe' do
      expect { Metasm::PE.decode(appender.generate_pe) }.to_not raise_exception
    end

    context 'the generated exe' do
      let(:generated_pe) { appender.generate_pe }
      let(:exe) { Metasm::PE.decode(generated_pe) }
      let(:original_exe) { Metasm::PE.decode_file(template) }

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

      it 'leaves the original entrypoint unchanged' do
        expect(exe.optheader.entrypoint).to eq(original_exe.optheader.entrypoint)
      end

      it 'appends the raw payload bytes' do
        expect(exe.sections.last.encoded.data.byteslice(0, payload.bytesize)).to eq(payload)
      end

      it 'records the generated section name' do
        generated_pe

        expect(appender.section_name).to match(/\A\.[a-z]{4}\z/)
      end
    end

    context 'when configured with a section name and data characteristics' do
      let(:template) do
        File.join(File.dirname(__FILE__), '..', '..', '..', '..', '..', 'data', 'templates', 'template_x86_windows_svc.exe')
      end

      let(:payload) { 'A'.b * 9000 }
      let(:payload_section_data) { [payload.bytesize].pack('V') + payload }
      let(:opts) do
        {
          template: template,
          payload: payload_section_data,
          arch: :x86,
          section_name: 'paysec',
          section_characteristics: %w[CONTAINS_DATA MEM_READ]
        }
      end

      let(:generated_pe) { appender.generate_pe }
      let(:exe) { Metasm::PE.decode(generated_pe) }
      let(:original_exe) { Metasm::PE.decode_file(template) }
      let(:payload_section) { exe.sections.find { |section| section.name == '.paysec' } }

      it 'leaves the original entrypoint unchanged' do
        expect(exe.optheader.entrypoint).to eq(original_exe.optheader.entrypoint)
      end

      it 'appends a named, readable data section containing the payload' do
        expect(payload_section).not_to be_nil
        expect(payload_section.characteristics).to include('CONTAINS_DATA', 'MEM_READ')
        expect(payload_section.characteristics).not_to include('MEM_EXECUTE', 'MEM_WRITE')

        section_data = payload_section.encoded.data
        expect(section_data.byteslice(0, 4).unpack1('V')).to eq(payload.bytesize)
        expect(section_data.byteslice(4, payload.bytesize)).to eq(payload)
      end

      it 'records the configured section name' do
        generated_pe

        expect(appender.section_name).to eq('.paysec')
      end
    end

    context 'when configured with a legacy secname option' do
      let(:opts) do
        {
          template: template,
          payload: payload,
          arch: :x86,
          secname: 'oldsec'
        }
      end

      let(:exe) { Metasm::PE.decode(appender.generate_pe) }

      it 'uses the configured name for the appended section' do
        expect(exe.sections.last.name).to eq('.oldsec')
        expect(appender.section_name).to eq('.oldsec')
        expect(appender.secname).to eq('.oldsec')
      end
    end
  end
end
