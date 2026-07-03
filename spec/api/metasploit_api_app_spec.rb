require 'spec_helper'
require 'rack/test'

RSpec.describe Msf::WebServices::MetasploitApiApp do
  include Rack::Test::Methods
  include_context 'Msf::DBManager'

  let(:app) { described_class.new }

  before(:example) do
    header 'Content-Type', 'application/json'
    # Create a user so authentication is enforced (auth_initialized = true).
    # Without this, the API auto-succeeds auth for all requests.
    Mdm::User.where(username: 'test_user').first_or_create!(
      crypted_password: BCrypt::Password.create('test_password'),
      admin: false
    )
  end

  describe 'host authorization' do
    it 'does not reject requests with a 403 Host not permitted error' do
      get '/api/v1/hosts'
      expect(last_response.status).not_to eq(403)
      expect(last_response.body).not_to include('Host not permitted')
    end
  end

  describe 'authentication' do
    it 'returns 401 for unauthenticated requests to protected endpoints' do
      get '/api/v1/hosts'
      expect(last_response.status).to eq(401)
    end

    it 'returns a JSON error body for unauthenticated requests' do
      get '/api/v1/hosts'
      json = JSON.parse(last_response.body)
      expect(json).to have_key('error')
      expect(json['error']['message']).to include('Authenticate to access this resource')
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
