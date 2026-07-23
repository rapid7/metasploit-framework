require 'spec_helper'

RSpec.describe 'Payload version compatibility integration' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:automatic_target_index) { 0 }
  let(:windows_2000_universal_index) { 1 }
  let(:windows_xp_sp0_index) { 2 }
  let(:windows_2003_index) { 3 }
  let(:windows_xp_sp2_index) { 4 }

  let(:exploit) do
    load_and_create_module(
      module_type: 'exploit',
      # Chosen as it has many targets that allow us to test the payload warning code paths.
      reference_name: 'windows/smb/ms08_067_netapi'
    )
  end

  let(:mock_module_info_without_minimum_versions) { { 'Name' => 'Mock Payload' } }
  let(:mock_module_info_with_minimum_versions) do
    {
      'Name' => 'Mock Payload',
      'SupportedVersions' => {
        'win' => [Msf::Module::VersionRange.new(min: Msf::WindowsVersion::XP_SP2)]
      }
    }
  end

  # Mock payload
  let(:payload_with_minimum_versions) do
    instance = instance_double(Msf::Payload)
    allow(instance).to receive(:supported_versions).and_return(mock_module_info_with_minimum_versions['SupportedVersions'])
    instance
  end

  let(:payload_without_minimum_versions) do
    instance = instance_double(Msf::Payload)
    allow(instance).to receive(:supported_versions).and_return(mock_module_info_without_minimum_versions['SupportedVersions'])
    instance
  end

  describe '#version_compatibility_warnings' do
    context 'when target is Windows 2000 (below Meterpreter minimum)' do
      before do
        exploit.datastore['TARGET'] = windows_2000_universal_index
      end

      it 'warns for payload with SupportedVersions' do
        warnings = exploit.version_compatibility_warnings(payload_with_minimum_versions)
        expect(warnings).to eq(['Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows 2000 (5.0.2195)'])
      end

      it 'does not warn for payload without SupportedVersions' do
        warnings = exploit.version_compatibility_warnings(payload_without_minimum_versions)
        expect(warnings).to be_empty
      end
    end

    context 'when target is Windows XP SP0/SP1 (below Meterpreter minimum)' do
      before do
        exploit.datastore['TARGET'] = windows_xp_sp0_index
      end

      it 'warns for payload with SupportedVersions' do
        warnings = exploit.version_compatibility_warnings(payload_with_minimum_versions)
        expect(warnings).to eq(["Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows XP (5.1.2600.0)"])
      end
    end

    context 'when target is Windows XP SP2 (meets Meterpreter minimum)' do
      before do
        exploit.datastore['TARGET'] = windows_xp_sp2_index
      end

      it 'does not warn for payload with SupportedVersions' do
        warnings = exploit.version_compatibility_warnings(payload_with_minimum_versions)
        expect(warnings).to be_empty
      end
    end

    context 'when target is Automatic (no PlatformVersions declared)' do
      before do
        exploit.datastore['TARGET'] = automatic_target_index
      end

      it 'warns with the lowest common denominator' do
        warnings = exploit.version_compatibility_warnings(payload_with_minimum_versions)
        expect(warnings).to eq(["Payload requires Windows version within a supported range (minimum Windows XP Service Pack 2 (5.1.2600.2)), but the target provides Windows 2000 (5.0.2195)"])
      end
    end

    context 'when target is Windows 2003 SP0 (above Meterpreter minimum)' do
      before do
        exploit.datastore['TARGET'] = windows_2003_index
      end

      it 'does not warn for payload with SupportedVersions' do
        warnings = exploit.version_compatibility_warnings(payload_with_minimum_versions)
        expect(warnings).to be_empty
      end
    end
  end
end
