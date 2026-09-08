require 'spec_helper'
require_relative '../riscv_xor_encoder_examples'

RSpec.describe 'modules/encoders/riscv32le/byte_xori' do
  it_behaves_like 'riscv byte_xori encoder', 'riscv32le/byte_xori'
end
