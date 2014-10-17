require 'spec_helper'

describe Msf::Author do
  context 'Known' do
    subject(:known) {
      described_class::Known
    }
    
    it { is_expected.to be_a Hash }
  end
  
  it { is_expected.to respond_to :== }
  it { is_expected.to respond_to :email }
  it { is_expected.to respond_to :email= }
  it { is_expected.to respond_to :from_s }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :name= }
  it { is_expected.to respond_to :to_s }
  
  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :from_s }
    it { is_expected.to respond_to :transform }
  end
end