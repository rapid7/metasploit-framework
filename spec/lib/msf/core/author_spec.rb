require 'spec_helper'

describe Msf::Author do
  it 'is an alias for Msf::Module::Author' do
    expect(described_class.name).to eq('Msf::Module::Author')
  end
end