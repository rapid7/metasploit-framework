require 'spec_helper'
require 'rex/exploitation/jsobfu'

describe Rex::Exploitation::JSObfu do

  subject(:jsobfu) do
    described_class.new("")
  end

  describe '#random_var_name' do
    subject(:random_var_name) { jsobfu.random_var_name }

    it { should be_a String }
    it { should_not be_empty }

    it 'is composed of _, $, alphanumeric chars' do
      20.times { expect(jsobfu.random_var_name).to match(/\A[a-zA-Z0-9$_]+\Z/) }
    end

    it 'does not start with a number' do
      20.times { expect(jsobfu.random_var_name).not_to match(/\A[0-9]/) }
    end

    context 'when a reserved word is generated' do
      let(:reserved)  { described_class::RESERVED_KEYWORDS.first }
      let(:random)    { 'abcdef' }
      let(:generated) { [reserved, reserved, reserved, random] }

      before do
        jsobfu.stub(:random_string) { generated.shift }
      end

      it { should be random }
    end

    context 'when a non-unique random var is generated' do
      let(:preexisting) { 'preexist' }
      let(:random)      { 'abcdef' }
      let(:vars)        { { 'jQuery' => preexisting } }
      let(:generated)   { [preexisting, preexisting, preexisting, random] }

      before do
        jsobfu.stub(:random_string) { generated.shift }
        jsobfu.instance_variable_set("@vars", vars)
      end

      it { should be random }
    end
  end

end
