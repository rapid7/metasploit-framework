require 'spec_helper'

describe Msf::SiteReference do
  it 'is an alias for Msf::Module::SiteReference' do
    expect(described_class.name).to eq('Msf::Module::SiteReference')
  end
end