# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/acpp'

RSpec.describe Rex::Proto::ACPP::Message do

  subject(:message) do
    described_class.new
  end

  # retrieve_public.bin has the contents of a message type 20 (retrieve
  # settings) message with a password of public.  There is no payload.
  let(:retrieve_public_bin) do
    IO.read(File.join(File.dirname(__FILE__), 'retrieve_public.bin'))
  end

  let(:retrieve_public_message) do
    message.password = 'public'
    message.type = 20
    message
  end

  describe '#==' do
    it 'considers two different objects composed of equal parts equal' do
      message2 = described_class.new
      message2.password = 'public'
      message2.type = 20
      expect(message2).to eq(retrieve_public_message)
    end
    it 'considers two different objects composed of different parts unequal' do
      message3 = described_class.new
      message3.type = 1
      message3.password = 'private'
      expect(message3).not_to eq(retrieve_public_message)
    end
  end

  describe '#to_s' do
    it 'encodes properly' do
      expect(retrieve_public_bin).to eq(retrieve_public_message.to_s)
    end
  end

  describe '#decode' do
    it 'fails to decode if the message is the wrong size' do
      small = Rex::Text.rand_text_alpha(100)
      large = Rex::Text.rand_text_alpha(200)
      expect { described_class.decode(small) }.to raise_error(/size #{small.size}/i)
      expect { described_class.decode(large) }.to raise_error(/size #{large.size}/i)
    end
    it 'fails to decode if the required header is incorrect' do
      retrieve_public_bin[0,4] = 'blah'
      expect { described_class.decode(retrieve_public_bin) }.to raise_error(/header/i)
    end
    it 'decodes properly when the required checksum is correct' do
      expect(retrieve_public_message).to eq(described_class.decode(retrieve_public_bin))
      expect(retrieve_public_message).to eq(described_class.decode(retrieve_public_bin, true))
    end
    it 'decodes properly when the non-required checksum is correct' do
      expect(retrieve_public_message).to eq(described_class.decode(retrieve_public_bin, false))
    end
    it 'decodes properly when the message checksum is incorrect' do
      retrieve_public_bin[7,4] = "\x01\x02\x03\x04"
      expect { described_class.decode(retrieve_public_bin) }.to raise_error(/message checksum/i)
      expect { described_class.decode(retrieve_public_bin, true) }.to raise_error(/message checksum/i)
      expect(retrieve_public_message).to eq(described_class.decode(retrieve_public_bin, false))
    end
  end

  describe '#successful?' do
    it 'is successful when 0' do
      message = described_class.new
      message.status = 0
      expect(message.successful?).to be true
    end
    it 'is successful when !0' do
      message = described_class.new
      message.status = 1
      expect(message.successful?).to be false
    end
  end
end
