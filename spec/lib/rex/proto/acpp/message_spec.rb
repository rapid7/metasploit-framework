# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/acpp'

describe Rex::Proto::ACPP::Message do

  subject(:message) do
    described_class.new
  end

  # public.bin has the contents of a message type 20, password public message
  # with a 612-byte retrieve payload that happens to be in a different packet
  let(:retrieve_public_bin) do
    IO.read(File.join(File.dirname(__FILE__), 'retrieve_public.bin'))
  end

  let(:retrieve_public_message) do
    m = described_class.new
    m.password = 'public'
    m.type = 20
    m
  end

  describe '#to_s' do
    it 'encodes properly' do
      expect(retrieve_public_bin).to eq(retrieve_public_message.to_s)
    end
  end

  describe '#decode' do
    it 'decodes properly' do
      expect(retrieve_public_message).to eq(described_class.decode(retrieve_public_bin))
    end
  end
end
