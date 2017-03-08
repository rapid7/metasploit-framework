# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/mms/model'

RSpec.describe Rex::Proto::Mms::Client do

  let(:phone_numbers) { ['1112223333'] }

  let(:message) { 'message' }

  let(:attachment) { 'file.jpg' }

  let(:file_content) { 'content' }

  let(:subject) { 'subject' }

  let(:ctype) { 'ctype' }

  let(:carrier) { :verizon }

  let(:smtp_server) {
    Rex::Proto::Mms::Model::Smtp.new(
      address: 'example.com',
      port: 25,
      username: 'username',
      password: 'password'
    )
  }

  subject do
    Rex::Proto::Mms::Client.new(
      carrier: carrier,
      smtp_server: smtp_server
    )
  end

  describe '#initialize' do
    it 'sets carrier' do
      expect(subject.carrier).to eq(carrier)
    end

    it 'sets smtp server' do
      expect(subject.smtp_server).to eq(smtp_server)
    end
  end

  describe '#send_mms_to_phones' do
    before(:each) do
      smtp = Net::SMTP.new(smtp_server.address, smtp_server.port)
      allow(smtp).to receive(:start).and_yield
      allow(smtp).to receive(:send_message) { |args| @sent_message = args }
      allow(Net::SMTP).to receive(:new).and_return(smtp)
      allow(File).to receive(:read).and_return(file_content)
    end

    it 'sends an mms message' do
      subject.send_mms_to_phones(phone_numbers, subject, message, attachment, ctype)
      expect(@sent_message).to include('MIME-Version: 1.0')
    end
  end

end
