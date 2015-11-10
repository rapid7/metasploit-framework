require 'spec_helper'
require 'rex/post/meterpreter'

describe MetasploitPayloads do
  it 'is available' do
    expect(described_class).to eq(MetasploitPayloads)
  end
end
