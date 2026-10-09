# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'
require 'rex/peparsey'

RSpec.describe Msf::Util::EXE::Windows::Aarch64 do
  let(:payload) { 'A'.b * 32 }

  describe '.to_winaarch64pe' do
    # The EXE generator only tolerates payloads up to WINAARCH64_PAYLOAD_SPACE
    # (currently 8192) bytes because that is the size of the fixed payload[]
    # buffer compiled into template_aarch64_windows.exe. The oversize test uses
    # 8193 bytes so any change to WINAARCH64_PAYLOAD_SPACE that widens the
    # buffer will surface here.
    let(:max_payload_space) { Msf::Util::EXE::Windows::Aarch64::ClassMethods::WINAARCH64_PAYLOAD_SPACE }
    let(:template) do
      File.expand_path('../../../../../../data/templates/template_aarch64_windows.exe', __dir__)
    end

    let(:generated_exe) do
      Msf::Util::EXE.to_winaarch64pe(nil, payload, template: template)
    end

    let(:template_bytes) { File.binread(template) }
    let(:payload_offset) { template_bytes.index('PAYLOAD:') }

    it 'returns a Windows PE the same size as the template' do
      expect(generated_exe.bytesize).to eq(template_bytes.bytesize)
      expect(generated_exe.byteslice(0, 2)).to eq('MZ')
    end

    it 'injects the shellcode at the PAYLOAD: tag offset' do
      expect(payload_offset).not_to be_nil
      expect(generated_exe.byteslice(payload_offset, payload.bytesize)).to eq(payload)
    end

    it 'leaves bytes before and after the payload buffer unchanged' do
      expect(generated_exe.byteslice(0, payload_offset)).to eq(template_bytes.byteslice(0, payload_offset))

      tail_offset = payload_offset + max_payload_space
      expect(generated_exe.byteslice(tail_offset..)).to eq(template_bytes.byteslice(tail_offset..))
    end

    it 'raises when the payload exceeds the template payload buffer' do
      oversized = 'B'.b * (max_payload_space + 1)
      expect { Msf::Util::EXE.to_winaarch64pe(nil, oversized, template: template) }
        .to raise_error(RuntimeError, /max size of #{max_payload_space} bytes/)
    end
  end

  describe '.to_winaarch64pe_dll' do
    let(:template) do
      File.expand_path('../../../../../../data/templates/template_aarch64_windows.dll', __dir__)
    end

    it 'produces an ARM64 DLL' do
      dll = Msf::Util::EXE.to_winaarch64pe_dll(nil, payload, template: template)
      pe = Rex::PeParsey::Pe.new_from_string(dll)
      expect(pe.hdr.file.Machine).to eq(Rex::PeParsey::PeBase::IMAGE_FILE_MACHINE_ARM64)
      expect(pe.hdr.file.Characteristics & 0x2000).to eq(0x2000) # IMAGE_FILE_DLL
    end

    it 'injects the shellcode at the PAYLOAD: tag offset' do
      template_bytes = File.binread(template)
      payload_offset = template_bytes.index('PAYLOAD:')
      dll = Msf::Util::EXE.to_winaarch64pe_dll(nil, payload, template: template)
      expect(payload_offset).not_to be_nil
      expect(dll.byteslice(payload_offset, payload.bytesize)).to eq(payload)
    end

    it 'raises when template injection is requested' do
      expect { Msf::Util::EXE.to_winaarch64pe_dll(nil, payload, inject: true) }
        .to raise_error(RuntimeError, /Template injection unsupported/)
    end

    it 'raises when the payload exceeds the selected DLL template' do
      oversized = 'B'.b * 4097
      expect { Msf::Util::EXE.to_winaarch64pe_dll(nil, oversized, template: template) }
        .to raise_error(RuntimeError, /max size of 4096 bytes/)
    end
  end

  describe 'to_executable_fmt dll' do
    it 'selects the AArch64 DLL generator' do
      dll = Msf::Util::EXE.to_executable_fmt(nil, ARCH_AARCH64, nil, payload, 'dll', {})
      pe = Rex::PeParsey::Pe.new_from_string(dll)
      expect(pe.hdr.file.Machine).to eq(Rex::PeParsey::PeBase::IMAGE_FILE_MACHINE_ARM64)
      expect(pe.hdr.file.Characteristics & 0x2000).to eq(0x2000) # IMAGE_FILE_DLL
    end
  end
end
