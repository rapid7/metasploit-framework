
shared_examples_for "an option" do |valid_values, invalid_values|
  subject do
    described_class.new("name")
  end

  context "with valid values" do
    valid_values.each do |valid_value, normalized_value|
      it "should be valid and normalize appropriately: #{valid_value}" do
        subject.valid?(valid_value).should be_true
        subject.normalize(valid_value).should == normalized_value
      end
    end
  end

  context "with invalid values" do
    invalid_values.each do |invalid_value|
      it "should not be valid: #{invalid_value}" do
        subject.valid?(invalid_value).should be_false
      end
    end
  end

end

