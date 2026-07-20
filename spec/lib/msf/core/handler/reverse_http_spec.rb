require 'spec_helper'

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

  describe '#stop_handler' do
    let(:mock_service) { double('service') }
    let(:payload) { create_payload }

    context 'when add_resource raised and resource was not added' do
      before do
        payload.service = mock_service
        payload.resource_added = false
      end

      it 'does not remove the resource but still derefs the service' do
        expect(mock_service).not_to receive(:remove_resource)
        expect(mock_service).to receive(:deref)
        payload.stop_handler
        expect(payload.service).to be_nil
      end
    end

    context 'when the resource was successfully added' do
      before do
        payload.service = mock_service
        payload.resource_added = true
      end

      it 'removes the resource and derefs the service' do
        expect(mock_service).to receive(:remove_resource).with('/')
        expect(mock_service).to receive(:deref)
        payload.stop_handler
        expect(payload.service).to be_nil
        expect(payload.resource_added).to eq(false)
      end
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
