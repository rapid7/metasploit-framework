require 'spec_helper'
require 'rex/exploitation/jsobfu'

describe Rex::Exploitation::JSObfu::Scope do

  subject(:scope) do
    described_class.new()
  end

  describe '#random_var_name' do
    subject(:random_var_name) { scope.random_var_name }

    it { should be_a String }
    it { should_not be_empty }

    it 'is composed of _, $, alphanumeric chars' do
      20.times { expect(scope.random_var_name).to match(/\A[a-zA-Z0-9$_]+\Z/) }
    end

    it 'does not start with a number' do
      20.times { expect(scope.random_var_name).not_to match(/\A[0-9]/) }
    end

    context 'when a reserved word is generated' do
      let(:reserved)  { described_class::RESERVED_KEYWORDS.first }
      let(:random)    { 'abcdef' }
      let(:generated) { [reserved, reserved, reserved, random] }

      before do
        scope.stub(:random_string) { generated.shift }
      end

      it { should eq random }
    end

    context 'when a non-unique random var is generated' do
      let(:preexisting) { 'preexist' }
      let(:random)      { 'abcdef' }
      let(:generated)   { [preexisting, preexisting, preexisting, random] }

      before do
        scope.stub(:random_string) { generated.shift }
        scope[preexisting] = 1
      end

      it { should eq random }
    end
  end

end
