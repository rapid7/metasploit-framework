# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Util::EXE::Windows::Common do
  let(:payload) { 'B'.b * 9000 }
  let(:service_name) { 'TestSvc' }

  [
    ['.to_win32pe_service', :to_win32pe_service, 'template_x86_windows_svc.exe', 32],
    ['.to_win64pe_service', :to_win64pe_service, 'template_x64_windows_svc.exe', 64]
  ].each do |description, method_name, template_name, bitsize|
    describe description do
      let(:template) do
        File.expand_path("../../../../../../data/templates/#{template_name}", __dir__)
      end

      let(:generated_exe) do
        Msf::Util::EXE.public_send(
          method_name,
          nil,
          payload,
          template: template,
          servicename: service_name,
          section_name: 'paysec'
        )
      end

      let(:decoded_pe) { Metasm::PE.decode(generated_exe) }
      let(:payload_section) { decoded_pe.sections.find { |section| section.name == '.paysec' } }

      it 'generates a valid service PE with a large payload section' do
        expect(payload.bytesize).to be > 8192
        expect { decoded_pe }.not_to raise_error
        expect(decoded_pe.bitsize).to eq(bitsize)

        expect(payload_section).not_to be_nil

        expect(payload_section.virtsize).to be >= payload.bytesize
        expect(payload_section.encoded.data.byteslice(0, payload.bytesize)).to eq(payload)
      end

      it 'patches the service name and payload section tag' do
        expect(generated_exe).to include([service_name].pack('a11'))
        expect(generated_exe).to include(['.paysec'].pack('a8'))
        expect(generated_exe).not_to include('SERVICENAME')
        expect(generated_exe).not_to include('.payload')
      end

      it 'randomizes the default payload section name and patches the .payload tag' do
        exe = Msf::Util::EXE.public_send(method_name, nil, payload, template: template)
        pe = Metasm::PE.decode(exe)
        randomized_section = pe.sections.find do |section|
          section.name.match?(/\A\.[a-z]{4}\z/)
        end

        expect(randomized_section).not_to be_nil
        expect(exe).not_to include('.payload')
      end
    end
  end
end
