require 'rex/exploitation/jsobfu'

describe Rex::Exploitation::JSObfu do

  subject(:jsobfu) do
    described_class.new("")
  end

  describe '#random_var_name' do
    subject(:random_var_name) { jsobfu.random_var_name }

    it { should be_a String }
    it { should_not be_empty }

    context 'when a reserved word is generated' do
      let(:reserved)  { described_class::RESERVED_KEYWORDS.first }
      let(:random)    { 'abcdef'}
      let(:generated) { [reserved, reserved, reserved, random] }

      before do
        Rex::Text.stub(:rand_text_alpha) { generated.shift }
      end

      it { should eq random }
    end

    context 'when a non-unique random var is generated' do
      let(:preexisting) { 'preexist' }
      let(:random)      { 'abcdef' }
      let(:vars)        { { 'jQuery' => preexisting } }
      let(:generated)   { [preexisting, preexisting, preexisting, random] }

      before do
        Rex::Text.stub(:rand_text_alpha) { generated.shift }
        jsobfu.instance_variable_set("@vars", vars)
      end

      it { should eq random }
    end
  end

end
