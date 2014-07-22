require 'spec_helper'
require 'rex/post/meterpreter'

describe MeterpreterBinaries do
  it 'is available' do
    expect(described_class).to eq(MeterpreterBinaries)
  end
end
