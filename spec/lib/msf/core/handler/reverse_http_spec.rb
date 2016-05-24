require 'spec_helper'
require 'msf/core/handler/reverse_http'

RSpec.describe Msf::Handler::ReverseHttp do

  def create_payload(info = {})
    klass = Class.new(Msf::Payload)
    klass.include described_class
    mod = klass.new(info)
    datastore.each { |k, v| mod.datastore[k] = v }
    mod
  end

  let(:datastore) do
    Hash.new
  end

  describe '#luri' do
    subject(:luri) do
      create_payload.luri
    end

    context 'with leading and trailing slash' do
      let(:datastore) do
        { 'LURI' => '/asdf/' }
      end

      specify 'is a string' do
        expect(luri).to be_a(String)
      end

      specify 'keeps leading, removes trailing slash' do
        expect(luri).to eql('/asdf')
      end

    end

    context 'with a leading slash' do
      let(:datastore) do
        { 'LURI' => '/asdf' }
      end

      specify 'is a string' do
        expect(luri).to be_a(String)
      end

      specify 'maintains one slash' do
        expect(luri).to eql('/asdf')
      end

    end

    context 'with a trailing slash' do
      let(:datastore) do
        { 'LURI' => 'asdf/' }
      end

      specify 'is a string' do
        expect(luri).to be_a(String)
      end

      specify 'adds leading, removes trailing slash' do
        expect(luri).to eql('/asdf')
      end

    end

    context 'just a slash' do
      let(:datastore) do
        { 'LURI' => '/' }
      end

      specify 'is a string' do
        expect(luri).to be_a(String)
      end

      specify 'just a slash' do
        expect(luri).to eql('/')
      end
    end

  end

end
