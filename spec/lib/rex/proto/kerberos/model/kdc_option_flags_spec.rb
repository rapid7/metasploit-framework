# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Model::KdcOptionFlags do
  let(:subject) { described_class.new(0x50e10000) }

  describe '.from_flags' do
    it 'supports initialization from an array of values' do
      result = described_class.from_flags(
        [
          Rex::Proto::Kerberos::Model::KdcOptionFlag::FORWARDABLE,
          Rex::Proto::Kerberos::Model::KdcOptionFlag::RENEWABLE,
          Rex::Proto::Kerberos::Model::KdcOptionFlag::CANONICALIZE,
          Rex::Proto::Kerberos::Model::KdcOptionFlag::RENEWABLE_OK,
        ]
      )

      expect(result).to eq(described_class.new(0x40810010))
      expect(result.enabled_flag_names).to eq(%i[FORWARDABLE RENEWABLE CANONICALIZE RENEWABLE_OK])
    end
  end

  describe '#enabled_flag_names' do
    it 'returns an array of the enabled human readable flag names' do
      expect(subject.enabled_flag_names).to eq(%i[FORWARDABLE PROXIABLE RENEWABLE INITIAL PRE_AUTHENT CANONICALIZE])
    end
  end

  describe '#include?' do
    it 'returns true when the flag is enabled' do
      expect(subject).to include(Rex::Proto::Kerberos::Model::KdcOptionFlag::FORWARDABLE)
    end

    it 'returns false when the flag is not enabled' do
      expect(subject).to_not include(Rex::Proto::Kerberos::Model::KdcOptionFlag::ALLOW_POST_DATE)
    end
  end

  describe '#==' do
    it 'returns true for an equivalent integer value' do
      expect(subject).to eq(0x50e10000)
    end

    it 'returns false for a different integer value' do
      expect(subject).to_not eq(0x60e10000)
    end

    it 'returns true for an equivalent object value' do
      expect(subject).to eq(described_class.new(0x50e10000))
    end

    it 'returns false for a different object value' do
      expect(subject).to_not eq(described_class.new(0x50e10001))
    end
  end
end
