require 'spec_helper'
require 'rex/post/meterpreter'

RSpec.describe MetasploitPayloads do
  it 'is available' do
    expect(described_class).to eq(MetasploitPayloads)
  end
end
