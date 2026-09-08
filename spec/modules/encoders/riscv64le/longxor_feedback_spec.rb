require 'spec_helper'
require_relative '../riscv_xor_encoder_examples'

RSpec.describe 'modules/encoders/riscv64le/longxor_feedback' do
  it_behaves_like 'riscv longxor_feedback encoder', 'riscv64le/longxor_feedback'
end
