
shared_examples_for "an option" do |valid_values, invalid_values|
  subject do
    described_class.new("name")
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

