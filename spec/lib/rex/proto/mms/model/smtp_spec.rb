# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/mms/model'

RSpec.describe Rex::Proto::Mms::Model::Smtp do

  let(:address)     { 'example.com' }
  let(:port)        { 25 }
  let(:username)    { 'username' }
  let(:password)    { 'password' }
  let(:login_type)  { :login }
  let(:from)        { 'from' }
  let(:helo_domain) { 'example.com'}

  subject do
    Rex::Proto::Mms::Model::Smtp.new(
      address: address,
      port: port,
      username: username,
      password: password,
      login_type: login_type,
      from: from,
      helo_domain: helo_domain
    )
  end

  describe '#initialize' do
    it 'sets address' do
      expect(subject.address).to eq(address)
    end

    it 'sets port' do
      expect(subject.port).to eq(port)
    end

    it 'sets username' do
      expect(subject.username).to eq(username)
    end

    it 'sets password' do
      expect(subject.password).to eq(password)
    end

    it 'sets login_type' do
      expect(subject.login_type).to eq(login_type)
    end

    it 'sets from' do
      expect(subject.from).to eq(from)
    end

    it 'sets helo domain' do
      expect(subject.helo_domain).to eq(helo_domain)
    end
  end

end
