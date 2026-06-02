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
    allow(instance).to receive(:instance_variable_get).with(:@module_info).and_return(payload_module_info)
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

  describe '#version_compatibility_warnings' do
    context 'when target does not declare RuntimeVersions' do
      let(:target_opts) { {} }
      let(:payload_module_info) { { 'Name' => 'Mock Payload', 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when payload does not declare MinimumVersions' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::Win2000 } } }
      let(:payload_module_info) { {} }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target is nil' do
      let(:target_opts) { nil }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      before do
        allow(subject).to receive(:target).and_return(nil)
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target version is below payload minimum' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::Win2000 } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings.length).to eq(1)
        expect(warnings).to include('Payload requires Windows >= Windows XP Service Pack 2 (5.1.2600.2), but the minimum potentially provided by the target is Windows 2000 (5.0.2195)')
      end
    end

    context 'when target version equals payload minimum' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target version exceeds payload minimum' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::Win7_SP0 } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when versions are provided as strings' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => '5.0.2195' } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => '5.1.2600.2' } } }

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings.length).to eq(1)
        expect(warnings).to include('Payload requires Windows >= Windows XP Service Pack 2 (5.1.2600.2), but the minimum potentially provided by the target is Windows 2000 (5.0.2195)')
      end
    end

    context 'when runtime keys do not overlap' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Linux' => '5.4.0' } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple runtime keys' do
      let(:target_opts) do
        {
          'RuntimeVersions' => {
            'Windows' => Msf::WindowsVersion::XP_SP0,
            'Python' => '2.7'
          }
        }
      end
      let(:payload_module_info) do
        {
          'MinimumVersions' => {
            'Windows' => Msf::WindowsVersion::XP_SP2,
            'Python' => '3.4'
          }
        }
      end

      it 'returns warnings for each incompatible key' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings.length).to eq(2)
        expect(warnings).to include('Payload requires Windows >= Windows XP Service Pack 2 (5.1.2600.2), but the minimum potentially provided by the target is Windows XP (5.1.2600.0)')
        expect(warnings).to include('Payload requires Python >= Python (3.4), but the minimum potentially provided by the target is Python (2.7)')
      end
    end

    context 'when Windows XP SP0/SP1 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP0 } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings.length).to eq(1)
        expect(warnings).to include('Payload requires Windows >= Windows XP Service Pack 2 (5.1.2600.2), but the minimum potentially provided by the target is Windows XP (5.1.2600.0)')
      end
    end

    context 'when Windows XP SP2 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when Windows Server 2003 SP0 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::Server2003_SP0 } } }
      let(:payload_module_info) { { 'MinimumVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'returns no warnings because Server 2003 (5.2) is above XP SP2 (5.1)' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end
  end
end
