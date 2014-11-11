require 'spec_helper'

describe Msf::Platform do
  it 'is an alias for Msf::Module::Platform' do
    expect(described_class.name).to eq('Msf::Module::Platform')
  end
end