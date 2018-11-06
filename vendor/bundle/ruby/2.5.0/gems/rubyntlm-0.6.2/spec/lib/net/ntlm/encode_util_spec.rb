require 'spec_helper'

describe Net::NTLM::EncodeUtil do

  context '#encode_utf16le' do
    it 'should convert an ASCII string to UTF' do
      expect(Net::NTLM::EncodeUtil.encode_utf16le('Test'.encode(::Encoding::ASCII_8BIT).freeze)).to eq("T\x00e\x00s\x00t\x00")
    end
  end

  context '#decode_utf16le' do
    it 'should convert a UTF string to ASCII' do
      expect(Net::NTLM::EncodeUtil.decode_utf16le("T\x00e\x00s\x00t\x00".freeze)).to eq('Test')
    end
  end
end
