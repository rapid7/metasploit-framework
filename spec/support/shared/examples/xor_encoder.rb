shared_examples_for 'an xor encoder' do |keysize|

	it "should encode one block" do
		# Yup it returns one of its arguments in an array... Because spoon.
		encoded, key = described_class.encode("A"*keysize, "A"*keysize)
		encoded.should eql("\x00"*keysize)

		encoded, key = described_class.encode("\x0f"*keysize, "\xf0"*keysize)
		encoded.should eql("\xff"*keysize)

		encoded, key = described_class.encode("\xf7"*keysize, "\x7f"*keysize)
		encoded.should eql("\x88"*keysize)
	end

	it "should encode multiple blocks" do
		encoded, key = described_class.encode("\xf7"*keysize*40, "\x7f"*keysize)
		encoded.should eql("\x88"*keysize*40)
	end

end
