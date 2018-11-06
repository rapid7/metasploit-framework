require 'spec_helper'

describe WindowsError::ErrorCode do

  subject(:error_code) { described_class.new(name, value, description) }
  let(:name) { 'STATUS_TIMEOUT' }
  let(:value) { 0x00000102 }
  let(:description) { 'The given Timeout interval expired.' }

  context 'with a non-number value' do
    let(:value) { 'Bogus' }

    it 'will raise an ArgumentError' do
      expect { described_class.new(name, value, description) }.to raise_error ArgumentError, 'Invalid Error Code Value!'
    end
  end

  context 'with a non-string description' do
    let(:description) { 42 }

    it 'will raise an ArgumentError' do
      expect { described_class.new(name, value, description) }.to raise_error ArgumentError, 'Invalid Error Description!'
    end
  end

  context 'with an empty string description' do
    let(:description) { '' }

    it 'will raise an ArgumentError' do
      expect { described_class.new(name, value, description) }.to raise_error ArgumentError, 'Invalid Error Description!'
    end
  end

  context 'with a non-string name' do
    let(:name) { 42 }

    it 'will raise an ArgumentError' do
      expect { described_class.new(name, value, description) }.to raise_error ArgumentError, 'Invalid Error Name!'
    end
  end

  context 'with an empty string name' do
    let(:name) { '' }

    it 'will raise an ArgumentError' do
      expect { described_class.new(name, value, description) }.to raise_error ArgumentError, 'Invalid Error Name!'
    end
  end

  it 'sets #name based on the initializer' do
    expect(error_code.name).to eq name
  end

  it 'sets #value based on the initializer' do
    expect(error_code.value).to eq value
  end

  it 'sets #description based on the initializer' do
    expect(error_code.description).to eq description
  end

  describe '#==' do
    let(:invalid_str) { 'foo' }

    it 'raises an ArgumentError for an invalid comparison' do
      expect { error_code == invalid_str }.to raise_error ArgumentError, "Cannot compare a WindowsError::ErrorCode to a #{invalid_str.class}"
    end

    context 'when passed a Integer' do
      let(:fixnum_value) { 258 }
      let(:other_fixnum) { 42 }

      it 'returns true if equal to the #value' do
        expect(error_code == fixnum_value).to eq true
      end

      it 'returns false if not equal to the #value' do
        expect(error_code == other_fixnum).to eq false
      end
    end

    context 'when passed another error code' do
      let(:matching_error_code) { described_class.new(name, value, description) }
      let(:other_error_code) { described_class.new(name, 42, description) }

      it 'returns true when the values match' do
        expect(error_code == matching_error_code).to eq true
      end

      it 'returns false when the values do not match' do
        expect(error_code == other_error_code).to eq false
      end
    end
  end

  describe '#to_s' do
    it 'outputs all of the relvant data in one useful string' do
      expect(error_code.to_s).to eq '(0x00000102) STATUS_TIMEOUT: The given Timeout interval expired.'
    end
  end
  
end
