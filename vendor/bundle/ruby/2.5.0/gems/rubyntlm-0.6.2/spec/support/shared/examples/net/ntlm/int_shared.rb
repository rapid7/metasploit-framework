shared_examples_for 'an integer field' do  |values|

  subject do
    described_class.new({
      :value => values[:default],
      :active => true
    })
  end

  context '#serialize' do
    it 'should serialize properly with an integer value' do
      expect(subject.serialize).to eq(values[:default_hex])
    end

    it 'should raise an Exception for a String' do
      subject.value = 'A'
      expect {subject.serialize}.to raise_error
    end

    it 'should raise an Exception for Nil' do
      subject.value = nil
      expect {subject.serialize}.to raise_error
    end
  end

  context '#parse' do
    it "should parse a raw #{values[:bits].to_s}-bit integer from a string" do
      expect(subject.parse(values[:alt_hex])).to eq(values[:size])
      expect(subject.value).to eq(values[:alt])
    end

    it "should use an offset to find the #{values[:bits].to_s}-bit integer in the string" do
      expect(subject.parse("Value:#{values[:alt_hex]}",6)).to eq(values[:size])
      expect(subject.value).to eq(values[:alt])
    end

    it 'should return 0 and not change the value if the string is not big enough' do
      expect(subject.parse(values[:small])).to eq(0)
      expect(subject.value).to eq(values[:default])
    end
  end

end
