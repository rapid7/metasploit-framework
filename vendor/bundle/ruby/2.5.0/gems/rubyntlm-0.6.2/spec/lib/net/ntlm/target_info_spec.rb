require 'spec_helper'

describe Net::NTLM::TargetInfo do
  let(:key1) { Net::NTLM::TargetInfo::MSV_AV_NB_COMPUTER_NAME }
  let(:value1) { 'some data' }
  let(:key2) { Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME }
  let(:value2) { 'some other data' }  
  let(:data) do
    dt = key1.dup
    dt << [value1.length].pack('S')
    dt << value1
    dt << key2.dup
    dt << [value2.length].pack('S')
    dt << value2
    dt << Net::NTLM::TargetInfo::MSV_AV_EOL
    dt << [0].pack('S')
    dt.force_encoding(Encoding::ASCII_8BIT)
  end

  subject { Net::NTLM::TargetInfo.new(data) }

  describe 'invalid data' do

    context 'invalid pair id' do
      let(:data) { "\xFF\x00" }

      it 'returns an error' do
        expect{subject}.to raise_error Net::NTLM::InvalidTargetDataError
      end    
    end
  end

  describe '#av_pairs' do

    it 'returns the pair values with the given keys' do
      expect(subject.av_pairs[key1]).to eq value1
      expect(subject.av_pairs[key2]).to eq value2
    end

    context "target data is nil" do
      subject { Net::NTLM::TargetInfo.new(nil) }

      it 'returns the pair values with the given keys' do
        expect(subject.av_pairs).to be_empty
      end
    end
  end

  describe '#to_s' do
    let(:data) do
      dt = key1.dup
      dt << [value1.length].pack('S')
      dt << value1
      dt << key2.dup
      dt << [value2.length].pack('S')
      dt << value2
      dt.force_encoding(Encoding::ASCII_8BIT)
    end
    let(:new_key) { Net::NTLM::TargetInfo::MSV_AV_CHANNEL_BINDINGS }
    let(:new_value) { 'bindings' }
    let(:new_data) do
      dt = data
      dt << new_key
      dt << [new_value.length].pack('S')
      dt << new_value
      dt << Net::NTLM::TargetInfo::MSV_AV_EOL
      dt << [0].pack('S')
      dt.force_encoding(Encoding::ASCII_8BIT)
    end

    it 'returns bytes with any new data added' do
      subject.av_pairs[new_key] = new_value
      expect(subject.to_s).to eq new_data
    end
  end
end
