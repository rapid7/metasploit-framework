require 'spec_helper'

RSpec.describe Msf::SiteReference do
  it 'is an alias for Msf::Module::SiteReference' do
    expect(described_class.name).to eq('Msf::Module::SiteReference')
  end
end