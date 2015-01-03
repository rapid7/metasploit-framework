# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/acpp'

describe Rex::Proto::ACPP::Message do

  subject(:message) do
    described_class.new
  end

  describe '#initialize' do
    it 'constructs properly' do
    end
  end

  describe '#encode' do
    it 'constructs properly' do
      message.password = 'public'
      message.type = 20

      File.open("/tmp/f", "wb") { |f| f.print(message.to_s) }
      expect(IO.read(File.join(File.dirname(__FILE__), 'public.bin'))).to eq(message.to_s)
    end
  end
end
