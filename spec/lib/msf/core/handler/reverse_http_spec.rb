require 'spec_helper'
require 'msf/core/handler/reverse_http'

RSpec.describe Msf::Handler::ReverseHttp do

  def create_payload(info = {})
    klass = Class.new(Msf::Payload)
    klass.include described_class
    mod = klass.new(info)
    mod.instance_eval do
      def ssl?
        false
      end
    end
    datastore.each { |k, v| mod.datastore[k] = v }
    mod
  end

  let(:datastore) do
    {'LHOST' => '127.0.0.1'}
  end

  describe '#payload_uri' do
    subject(:payload_uri) do
      create_payload.payload_uri
    end

    specify 'should be parseable as a URI' do
      expect {
        URI.parse(payload_uri)
      }.not_to raise_error
    end

  end

  describe '#luri' do
    subject(:luri) do
      create_payload.luri
    end

    context 'with leading and trailing slash' do
      let(:datastore) do
        { 'LURI' => '/asdf/' }
      end

      specify 'should be parseable as a URI' do
        expect {
          URI.parse(luri)
        }.not_to raise_error
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

      specify 'should be parseable as a URI' do
        expect {
          URI.parse(luri)
        }.not_to raise_error
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

      specify 'should be parseable as a URI' do
        expect {
          URI.parse(luri)
        }.not_to raise_error
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

      specify 'should be parseable as a URI' do
        expect {
          URI.parse(luri)
        }.not_to raise_error
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
