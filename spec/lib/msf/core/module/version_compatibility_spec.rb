# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Module::VersionCompatibility do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin

      attr_accessor :target
    end

    klass.new
  end

  let(:payload_instance) do
    instance = instance_double(Msf::Payload)
    allow(instance).to receive(:supported_versions).and_return(payload_module_info['SupportedVersions'])
    instance
  end

  let(:target_with_opts) do
    target = double(Msf::Target)
    allow(target).to receive(:opts).and_return(target_opts)
    allow(target).to receive(:name).and_return('Mock Target')
    target
  end

  before do
    allow(subject).to receive(:target).and_return(target_with_opts)
  end

  # Helper to build a single-range SupportedVersions entry with just a minimum version.
  def supported_versions_from_min(runtime, min)
    { runtime => [Msf::Module::VersionRange.new(min: min)] }
  end

  describe '#version_compatibility_warnings' do
    context 'when target does not declare PlatformVersions' do
      let(:target_opts) { {} }
      let(:payload_module_info) do
        { 'Name' => 'Mock Payload', 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when payload does not declare SupportedVersions' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Win2000 } } }
      let(:payload_module_info) { {} }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target is nil' do
      let(:target_opts) { nil }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      before do
        allow(subject).to receive(:target).and_return(nil)
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target version is below payload minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Win2000 } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(["Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows 2000 (5.0.2195)"])
      end
    end

    context 'when target version equals payload minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP2 } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target version exceeds payload minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Win7_SP0 } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when versions are provided as strings' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => '5.0.2195' } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', '5.1.2600.2') }
      end

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(["Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows 2000 (5.0.2195)"])
      end
    end

    context 'when runtime keys do not overlap' do
      let(:target_opts) { { 'PlatformVersions' => { 'linux' => '5.4.0' } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple runtime keys both incompatible' do
      let(:target_opts) do
        {
          'PlatformVersions' => {
            'win' => Msf::WindowsVersion::XP_SP0,
            'python' => '2.7'
          }
        }
      end
      let(:payload_module_info) do
        {
          'SupportedVersions' => {
            'win' => [Msf::Module::VersionRange.new(min: Msf::WindowsVersion::XP_SP2)],
            'python' => [Msf::Module::VersionRange.new(min: '3.4')]
          }
        }
      end

      it 'returns warnings for each incompatible runtime' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(
          [
            "Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows XP (5.1.2600.0)",
            "Payload requires Python version within a supported range (minimum Python (3.4)), but the target provides Python (2.7)"
          ]
        )
      end
    end

    context 'with multiple version ranges where target falls in a later range' do
      # Python payload: supports 2.5-2.7 and 3.1+
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '3.6' } } }
      let(:payload_module_info) do
        {
          'SupportedVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '2.7'),
              Msf::Module::VersionRange.new(min: '3.1')
            ]
          }
        }
      end

      it 'returns no warnings because 3.6 is within the 3.1+ range' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple version ranges where target falls in the first range' do
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '2.6' } } }
      let(:payload_module_info) do
        {
          'SupportedVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '2.7'),
              Msf::Module::VersionRange.new(min: '3.1')
            ]
          }
        }
      end

      it 'returns no warnings because 2.6 is within the 2.5..2.7 range' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple version ranges where target falls in a gap' do
      # Python 3.0 is between 2.7 and 3.1 — unsupported
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '3.0' } } }
      let(:payload_module_info) do
        {
          'SupportedVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '2.7'),
              Msf::Module::VersionRange.new(min: '3.1')
            ]
          }
        }
      end

      it 'returns a warning because 3.0 is in the gap between ranges' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(["Payload requires Python version within a supported range (minimum Python (2.5)), but the target provides Python (3.0)"])
      end
    end

    context 'when Windows XP SP0/SP1 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP0 } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(["Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows XP (5.1.2600.0)"])
      end
    end

    context 'when Windows XP SP2 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP2 } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when Windows Server 2003 SP0 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Server2003_SP0 } } }
      let(:payload_module_info) do
        { 'SupportedVersions' => supported_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings because Server 2003 (5.2) is above XP SP2 (5.1)' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end
  end
end
