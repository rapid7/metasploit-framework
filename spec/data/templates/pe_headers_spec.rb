require 'spec_helper'
require 'rex/peparsey'

RSpec.describe 'PE template binaries' do
  templates_dir = File.expand_path('../../../../data/templates', __FILE__)

  # Architecture expectations keyed by filename pattern. Value is the expected
  # Machine field from the PE file header.
  ARCH_EXPECTATIONS = {
    /\btemplate_x86_windows(_svc|_old|_dccw_gdiplus|_mixed_mode)?(\.256kib)?\.(exe|dll)\z/ => Rex::PeParsey::PeBase::IMAGE_FILE_MACHINE_I386,
    /\btemplate_x64_windows(_svc|_dccw_gdiplus|_mixed_mode)?(\.256kib)?\.(exe|dll)\z/      => Rex::PeParsey::PeBase::IMAGE_FILE_MACHINE_AMD64,
    /\btemplate_aarch64_windows\.exe\z/                                                    => Rex::PeParsey::PeBase::IMAGE_FILE_MACHINE_ARM64
  }.freeze

  # Minimum subsystem version the EXE templates must support. DLLs are not
  # checked by the loader for this field, so we only enforce it on EXEs.
  # x86 EXEs must run on NT 4.0 (4.0); x64 EXEs must run on Server 2003 (5.2).
  EXE_VERSION_EXPECTATIONS = {
    /\btemplate_x86_windows(_svc)?\.exe\z/ => [4, 0],
    /\btemplate_x64_windows(_svc)?\.exe\z/ => [5, 2]
  }.freeze

  templates = Dir.glob(File.join(templates_dir, 'template_*_windows*.{exe,dll}')).sort

  it 'has the expected set of PE templates present' do
    expect(templates).not_to be_empty
  end

  templates.each do |path|
    name = File.basename(path)

    describe name do
      let(:pe) { Rex::PeParsey::Pe.new_from_file(path, true) }
      after { pe.close if pe.respond_to?(:close) }

      arch_pattern, expected_machine = ARCH_EXPECTATIONS.find { |re, _| name =~ re }

      if arch_pattern
        it "has Machine matching its filename (0x#{expected_machine.to_s(16)})" do
          expect(pe.hdr.file.Machine).to eq(expected_machine)
        end
      else
        it 'is covered by an architecture expectation' do
          fail "no architecture expectation matches #{name}; update ARCH_EXPECTATIONS"
        end
      end

      version_pattern, version_expect = EXE_VERSION_EXPECTATIONS.find { |re, _| name =~ re }
      if version_pattern
        expected_major, expected_minor = version_expect

        it "has subsystem version #{expected_major}.#{expected_minor} so it runs on legacy Windows" do
          actual = [pe.hdr.opt.MajorSubsystemVersion, pe.hdr.opt.MinorSubsystemVersion]
          expect(actual).to eq([expected_major, expected_minor])
        end

        it "has OS version #{expected_major}.#{expected_minor}" do
          actual = [pe.hdr.opt.MajorOperatingSystemVersion, pe.hdr.opt.MinorOperatingSystemVersion]
          expect(actual).to eq([expected_major, expected_minor])
        end
      end
    end
  end
end
