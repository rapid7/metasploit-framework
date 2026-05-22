require 'spec_helper'
require 'rack/test'

RSpec.describe Msf::WebServices::MetasploitApiApp do
  include Rack::Test::Methods
  include_context 'Msf::DBManager'

  let(:app) { described_class.new }

  before(:example) do
    header 'Content-Type', 'application/json'
  end

  describe 'host authorization' do
    it 'does not reject requests with a 403 Host not permitted error' do
      get '/api/v1/hosts'
      expect(last_response.status).not_to eq(403)
      expect(last_response.body).not_to include('Host not permitted')
    end
  end

  describe 'authentication' do
    it 'does not return 200 for unauthenticated requests to protected endpoints' do
      get '/api/v1/hosts'
      expect(last_response.status).not_to eq(200)
    end

    it 'returns a JSON response body' do
      get '/api/v1/hosts'
      expect { JSON.parse(last_response.body) }.not_to raise_error
    end
  end

  describe 'response headers' do
    it 'uses lowercase header keys' do
      get '/api/v1/hosts'
      raw_keys = last_response.headers.keys
      raw_keys.each do |key|
        expect(key).to eq(key.downcase), "Expected header '#{key}' to be lowercase"
      end
    end
  end
end
