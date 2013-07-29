# -*- coding:binary -*-

shared_examples_for "an option" do |valid_values, invalid_values, type|
  subject do
    described_class.new("name")
  end

  let(:required) { described_class.new('name', [true, 'A description here'])}
  let(:optional) { described_class.new('name', [false, 'A description here'])}

  it "should return a type of #{type}"  do
    subject.type.should == type
  end

  context 'when required' do
    it 'should not be valid for nil' do
      required.valid?(nil).should == false
    end
  end

  context 'when not required' do
    it 'it should be valid for nil' do
      optional.valid?(nil).should == true
    end
  end

  context "with valid values" do
    valid_values.each do |vhash|
			valid_value = vhash[:value]
			normalized_value = vhash[:normalized]

      it "should be valid and normalize appropriately: #{valid_value}" do
				block = Proc.new {
					subject.normalize(valid_value).should == normalized_value
					subject.valid?(valid_value).should be_true
				}
				if vhash[:pending]
					pending(vhash[:pending], &block)
				else
					block.call
				end
      end
    end
  end

  context "with invalid values" do
    invalid_values.each do |vhash|
			invalid_value = vhash[:value]
      it "should not be valid: #{invalid_value}" do
        block = Proc.new { subject.valid?(invalid_value).should be_false }
				if vhash[:pending]
					pending(vhash[:pending], &block)
				else
					block.call
				end
      end
    end
  end

end

