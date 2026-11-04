require 'spec_helper'
require 'rack/test'

RSpec.describe Msf::WebServices::MetasploitApiApp do
  include Rack::Test::Methods
  include_context 'Msf::DBManager'

  let(:app) { described_class.new }

  before(:example) do
    header 'Content-Type', 'application/json'
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

  describe 'when no users exist' do
    # msfdb creates the first web service user directly in the database before the service
    # starts, so no request may create an account unauthenticated - even with an empty users
    # table, which is otherwise a window for anyone who can reach the service first.
    before do
      Mdm::User.delete_all
    end

    it 'does not allow a user account to be created unauthenticated' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           { 'CONTENT_TYPE' => 'application/json' }
      expect(last_response.status).to eq(401)
    end

    context 'when a client tries to create an admin with a token of its choosing' do
      before do
        post '/api/v1/users',
             { username: 'attacker', password: 'Pw123456!', admin: true, persistence_token: 'attacker_token' }.to_json,
             { 'CONTENT_TYPE' => 'application/json' }
      end

      it 'does not create the account' do
        expect(Mdm::User.where(username: 'attacker')).not_to exist
      end

      it 'does not accept the chosen token' do
        get '/api/v1/users', {}, { 'HTTP_AUTHORIZATION' => 'Bearer attacker_token' }
        expect(last_response.status).to eq(401)
      end
    end

    it 'requires authentication for other endpoints' do
      get '/api/v1/hosts'
      expect(last_response.status).to eq(401)
    end

    it 'requires authentication to list users' do
      get '/api/v1/users'
      expect(last_response.status).to eq(401)
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
