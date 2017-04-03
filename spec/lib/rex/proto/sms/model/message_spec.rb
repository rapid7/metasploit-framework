require 'spec_helper'
require 'rex/proto/sms/model'

RSpec.describe Rex::Proto::Sms::Model::Message do

  let(:message)      { 'message' }
  let(:from)         { 'sender@example.com' }
  let(:to)           { 'receiver@example.com' }
  let(:sms_subject)  { 'subject' }

  subject do
    described_class.new(
      from: from,
      to: to,
      subject: sms_subject,
      message: message,
    )
  end

  describe '#initialize' do
    it 'sets message' do
      expect(subject.message).to eq(message)
    end

    it 'sets from' do
      expect(subject.from).to eq(from)
    end

    it 'sets to' do
      expect(subject.to).to eq(to)
    end

    it 'sets subject' do
      expect(subject.subject).to eq(sms_subject)
    end
  end

  describe '#to_s' do
    it 'returns the sms message' do
      expect(subject.to_s).to include(message)
    end
  end

end
