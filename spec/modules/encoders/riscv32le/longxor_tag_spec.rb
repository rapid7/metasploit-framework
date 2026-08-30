require 'spec_helper'
require_relative '../riscv_xor_encoder_examples'

RSpec.describe 'modules/encoders/riscv32le/longxor_tag' do
  it_behaves_like 'riscv longxor_tag encoder', 'riscv32le/longxor_tag'
end
