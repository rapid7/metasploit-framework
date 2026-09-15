require 'spec_helper'

RSpec.describe Msf::Module::RuntimeVersionInference do
  describe '.infer' do
    it 'infers the Windows runtime version from a target name' do
      result = described_class.infer('Windows 7 SP1')
      expect(result).to eq('Windows' => Msf::WindowsVersion::Win7_SP1)
    end

    it 'returns an empty hash for a generic name' do
      expect(described_class.infer('Windows x64')).to eq({})
    end

    it 'does not overwrite a runtime that is already set' do
      existing = { 'Windows' => Msf::WindowsVersion::XP_SP2 }
      expect(described_class.infer('Windows 7 SP1', existing: existing)).to eq({})
    end

    it 'skips inferrers whose platform does not match the declared platform' do
      # A name that would otherwise resolve to Windows, but the target is linux.
      result = described_class.infer('Windows Server 2016', platform_names: ['linux'])
      expect(result).to eq({})
    end

    it 'applies inferrers when the declared platform matches' do
      result = described_class.infer('Windows 7', platform_names: ['win'])
      expect(result).to eq('Windows' => Msf::WindowsVersion::Win7_SP0)
    end

    it 'falls back to name-based inference when no platform is declared' do
      result = described_class.infer('Windows 7', platform_names: nil)
      expect(result).to eq('Windows' => Msf::WindowsVersion::Win7_SP0)
    end
  end

  describe 'Inferrer' do
    let(:resolver) { ->(name) { name == 'match' ? Rex::Version.new('1.0') : nil } }
    subject(:inferrer) { described_class::Inferrer.new('Example', /osx|mac/i, resolver) }

    it 'delegates version resolution to its resolver' do
      expect(inferrer.infer('match')).to eq(Rex::Version.new('1.0'))
      expect(inferrer.infer('no match')).to be_nil
    end

    it 'is applicable when no platform names are supplied' do
      expect(inferrer.applicable_to_platforms?(nil)).to be(true)
      expect(inferrer.applicable_to_platforms?([])).to be(true)
    end

    it 'is applicable when a declared platform matches its pattern' do
      expect(inferrer.applicable_to_platforms?(['osx'])).to be(true)
    end

    it 'is not applicable when no declared platform matches its pattern' do
      expect(inferrer.applicable_to_platforms?(['linux'])).to be(false)
    end

    it 'is always applicable when it has no platform pattern' do
      ungated = described_class::Inferrer.new('Example', nil, resolver)
      expect(ungated.applicable_to_platforms?(['linux'])).to be(true)
    end
  end
end
