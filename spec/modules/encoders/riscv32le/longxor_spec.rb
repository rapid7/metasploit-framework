require 'spec_helper'
require_relative '../riscv_xor_encoder_examples'

RSpec.describe 'modules/encoders/riscv32le/longxor' do
  it_behaves_like 'riscv longxor encoder', 'riscv32le/longxor'
end
