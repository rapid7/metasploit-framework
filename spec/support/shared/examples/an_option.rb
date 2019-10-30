# -*- coding:binary -*-

RSpec.shared_examples_for "an option" do |valid_values, invalid_values, type|
  subject do
    described_class.new("name")
  end

  let(:required) { described_class.new('name', [true, 'A description here'])}
  let(:optional) { described_class.new('name', [false, 'A description here'])}

  it "should return a type of #{type}"  do
    expect(subject.type).to eq type
  end

  context 'when required' do
    it 'should not be valid for nil' do
      expect(required.valid?(nil)).to eq false
    end
  end

  context 'when not required' do
    it 'it should be valid for nil' do
      expect(optional.valid?(nil)).to eq true
    end
  end

  context "with valid values" do
    valid_values.each do |vhash|
      valid_value = vhash[:value]
      normalized_value = vhash[:normalized]

      it "should be valid and normalize appropriately: #{valid_value}" do
        block = Proc.new {
          expect(subject.normalize(valid_value)).to eq normalized_value
          expect(subject.valid?(valid_value)).to be_truthy
        }
        if vhash[:skip]
          skip(vhash[:skip], &block)
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
        block = Proc.new { expect(subject.valid?(invalid_value)).to be_falsey }
        if vhash[:skip]
          skip(vhash[:skip], &block)
        else
          block.call
        end
      end
    end
  end

end

