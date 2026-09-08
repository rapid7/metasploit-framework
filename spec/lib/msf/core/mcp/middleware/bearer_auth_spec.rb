# frozen_string_literal: true

require 'msf/core/mcp'
require 'rack'

RSpec.describe Msf::MCP::Middleware::BearerAuth do
  let(:token) { 's3cr3t' }
  let(:inner_app) { ->(_env) { [200, { 'Content-Type' => 'application/json' }, ['OK']] } }
  let(:middleware) { described_class.new(inner_app, auth_token: token) }

  def rack_env_for(authorization: nil)
    env = Rack::MockRequest.env_for('http://localhost:3000/mcp', method: 'POST')
    env['HTTP_AUTHORIZATION'] = authorization if authorization
    env
  end

  describe 'UNAUTHORIZED' do
    subject { described_class::UNAUTHORIZED }

    it 'has status 401' do
      expect(subject[0]).to eq(401)
    end

    it 'includes Content-Type application/json' do
      expect(subject[1]['Content-Type']).to eq('application/json')
    end

    it 'includes a WWW-Authenticate Bearer challenge' do
      expect(subject[1]['WWW-Authenticate']).to eq('Bearer realm="msfmcp"')
    end

    it 'has a JSON error body' do
      expect(subject[2]).to eq(['{"error":"Unauthorized"}'])
    end

    it 'is frozen' do
      expect(subject).to be_frozen
    end
  end

  describe '#call' do
    context 'with the correct Bearer token' do
      it 'delegates to the inner app and returns its response' do
        env = rack_env_for(authorization: "Bearer #{token}")
        status, _headers, body = middleware.call(env)

        expect(status).to eq(200)
        expect(body).to eq(['OK'])
      end
    end

    context 'with a wrong token value' do
      it 'returns 401' do
        env = rack_env_for(authorization: 'Bearer wrongtoken')
        status, headers, body = middleware.call(env)

        expect(status).to eq(401)
        expect(headers['WWW-Authenticate']).to eq('Bearer realm="msfmcp"')
        expect(body).to eq(['{"error":"Unauthorized"}'])
      end
    end

    context 'with no Authorization header' do
      it 'returns 401' do
        env = rack_env_for
        status, _headers, _body = middleware.call(env)

        expect(status).to eq(401)
      end
    end

    context 'with the wrong scheme' do
      it 'returns 401' do
        env = rack_env_for(authorization: "Basic #{token}")
        status, _headers, _body = middleware.call(env)

        expect(status).to eq(401)
      end
    end

    context 'with the correct token but wrong case for the scheme' do
      it 'returns 401' do
        env = rack_env_for(authorization: "bearer #{token}")
        status, _headers, _body = middleware.call(env)

        expect(status).to eq(401)
      end
    end

    context 'with trailing whitespace on the token' do
      it 'returns 401' do
        env = rack_env_for(authorization: "Bearer #{token} ")
        status, _headers, _body = middleware.call(env)

        expect(status).to eq(401)
      end
    end
  end
end
