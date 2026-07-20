# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Skip checksum validation feature flag' do
  it 'is registered in the FeatureManager' do
    expect(Msf::FeatureManager.instance.exists?('skip_checksum_validation')).to be true
  end

  it 'is disabled by default' do
    expect(Msf::FeatureManager.instance.enabled?('skip_checksum_validation')).to be false
  end

  it 'can be enabled' do
    Msf::FeatureManager.instance.set('skip_checksum_validation', true)
    expect(Msf::FeatureManager.instance.enabled?('skip_checksum_validation')).to be true
  ensure
    Msf::FeatureManager.instance.set('skip_checksum_validation', false)
  end
end
