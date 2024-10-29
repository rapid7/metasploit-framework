require 'spec_helper'
require 'rex/version'

# rubocop:disable Lint/DeprecatedGemVersion
RSpec.describe Rex::Version do
  context 'when version is nil' do
    let(:version) { nil }
    subject { Rex::Version.new(version) }

    it 'should be equivalent to a version of 0' do
      expect(subject).to eq Gem::Version.new(0)
    end

    it 'should be equivalent to a version of "0"' do
      expect(subject).to eq Gem::Version.new('0')
    end

    it 'should be equivalent to a version of empty string' do
      expect(subject).to eq Gem::Version.new('')
    end

    it 'should not be less than a version of 0' do
      expect(subject).not_to be < Gem::Version.new(0)
    end

    it 'should not be greater than a version of 0' do
      expect(subject).not_to be > Gem::Version.new(0)
    end

    it 'should be less than a version of "0.0.1"' do
      expect(subject).to be < Gem::Version.new('0.0.1')
    end

    it 'should not be greater than a version of "0.0.1"' do
      expect(subject).not_to be > Gem::Version.new('0.0.1')
    end
  end
end
# rubocop:enable Lint/DeprecatedGemVersion
