require 'spec_helper'
require 'net/dns/question'

RSpec.describe Net::DNS::Question do
  describe '#initialize' do
    it 'does not raise FrozenError when given a frozen name' do
      expect { described_class.new('localhost'.freeze) }.not_to raise_error
    end

    it 'strips whitespace without mutating the original frozen string' do
      name = ' localhost '.freeze
      question = described_class.new(name)
      expect(question.qName).to eq('localhost')
    end

    it 'raises QuestionNameError for an invalid name' do
      expect { described_class.new('not valid!'.freeze) }.to raise_error(QuestionNameError)
    end
  end
end
