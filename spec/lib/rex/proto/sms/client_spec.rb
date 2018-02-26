# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/sms/model'

RSpec.describe Rex::Proto::Sms::Client do

  let(:phone_numbers) { ['1112223333'] }

  let(:sms_subject) { 'subject' }

  let(:message) { 'message' }

  let(:carrier) { :verizon }

  let(:smtp_server) {
    Rex::Proto::Sms::Model::Smtp.new(
      address: 'example.com',
      port: 25,
      username: 'username',
      password: 'password'
    )
  }

  subject do
    Rex::Proto::Sms::Client.new(
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

  describe '#send_text_to_phones' do
    before(:each) do
      smtp = Net::SMTP.new(smtp_server.address, smtp_server.port)
      allow(smtp).to receive(:start).and_yield
      allow(smtp).to receive(:send_message) { |args| @sent_message = args }
      allow(Net::SMTP).to receive(:new).and_return(smtp)
    end

    it 'sends a text message' do
      subject.send_text_to_phones(phone_numbers, sms_subject, message)
      expect(@sent_message).to include(message)
    end
  end

end
