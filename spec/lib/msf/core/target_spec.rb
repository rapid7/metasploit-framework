require 'spec_helper'

RSpec.describe Msf::Target do
  it 'is an alias for Msf::Module::Target' do
    expect(described_class.name).to eq('Msf::Module::Target')
  end

  describe 'automatic runtime version tagging' do
    subject(:target) { described_class.new(name, opts) }

    let(:opts) { {} }

    context 'when the name specifies a single Windows version' do
      let(:name) { 'Windows 7 SP1' }

      it 'infers the Windows runtime version' do
        expect(target.runtime_versions).to eq('Windows' => Msf::WindowsVersion::Win7_SP1)
      end
    end

    context 'when the name is generic' do
      let(:name) { 'Windows x64' }

      it 'leaves the target untagged' do
        expect(target.runtime_versions).to be_nil
      end
    end

    context 'when the name references several versions' do
      let(:name) { 'Windows XP SP3 / Windows 7 SP1' }

      it 'leaves the target untagged' do
        expect(target.runtime_versions).to be_nil
      end
    end

    context 'when a Windows version is set manually' do
      let(:name) { 'Windows 7 SP1' }
      let(:opts) { { 'RuntimeVersions' => { 'Windows' => Msf::WindowsVersion::XP_SP2 } } }

      it 'preserves the manual value' do
        expect(target.runtime_versions).to eq('Windows' => Msf::WindowsVersion::XP_SP2)
      end
    end

    context 'when other runtime versions are set manually' do
      let(:name) { 'Windows 7 SP1' }
      let(:opts) { { 'RuntimeVersions' => { 'Python' => '3.6' } } }

      it 'adds the inferred Windows version alongside them' do
        expect(target.runtime_versions).to eq(
          'Python' => '3.6',
          'Windows' => Msf::WindowsVersion::Win7_SP1
        )
      end
    end

    context 'when the target platform is not Windows' do
      let(:name) { 'Windows Server 2016' }
      let(:opts) { { 'Platform' => 'linux' } }

      it 'does not infer a Windows version' do
        expect(target.runtime_versions).to be_nil
      end
    end

    context 'when the target platform is Windows' do
      let(:name) { 'Windows 7' }
      let(:opts) { { 'Platform' => 'win' } }

      it 'infers the Windows runtime version' do
        expect(target.runtime_versions).to eq('Windows' => Msf::WindowsVersion::Win7_SP0)
      end
    end
  end
end
