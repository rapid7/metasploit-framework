# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::WebServices::CredentialServlet do
  let(:request_context) do
    double('request_context').tap do |context|
      allow(context).to receive(:warden) { warden }
    end
  end
  let(:warden) { double('warden') }

  shared_examples 'an authenticated credential handler' do |handler|
    it 'authenticates before processing the request' do
      authentication_error = Class.new(StandardError)
      allow(warden).to receive(:authenticate!).and_raise(authentication_error)
      expect(request_context).not_to receive(:parse_json_request)

      expect { request_context.instance_exec(&described_class.public_send(handler)) }.to raise_error(authentication_error)
    end
  end

  describe '.update_credential' do
    it_behaves_like 'an authenticated credential handler', :update_credential
  end

  describe '.delete_credentials' do
    it_behaves_like 'an authenticated credential handler', :delete_credentials
  end
end
