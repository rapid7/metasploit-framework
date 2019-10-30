require 'spec_helper'
require 'rex/proto/mms/model'

RSpec.describe Rex::Proto::Mms::Model::Message do

  let(:message)      { 'message' }
  let(:content_type) { 'ctype' }
  let(:attachment)   { 'filepath.jpg' }
  let(:filecontent)  { 'file content' }
  let(:from)         { 'sender@example.com' }
  let(:to)           { 'receiver@example.com' }
  let(:mms_subject)  { 'subject' }

  before(:each) do
    allow(File).to receive(:read).and_return(filecontent)
  end

  subject do
    described_class.new(
      from: from,
      to: to,
      subject: mms_subject,
      message: message,
      content_type: content_type,
      attachment_path: attachment
    )
  end

  describe '#initialize' do
    it 'sets message' do
      expect(subject.message).to eq(message)
    end

    it 'sets content type' do
      expect(subject.content_type).to eq(content_type)
    end

    it 'sets attachment path' do
      expect(subject.attachment).to eq('ZmlsZSBjb250ZW50')
    end

    it 'sets from' do
      expect(subject.from).to eq(from)
    end

    it 'sets to' do
      expect(subject.to).to eq(to)
    end

    it 'sets subject' do
      expect(subject.subject).to eq(mms_subject)
    end
  end

  describe '#to_s' do
    it 'returns the mms message' do
      expect(subject.to_s).to include('MIME-Version: 1.0')

    end
  end

end
