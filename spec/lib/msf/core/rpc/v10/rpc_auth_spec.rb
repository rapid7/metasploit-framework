# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Auth do
  include_context 'Msf::Simple::Framework'

  let(:service) do
    Msf::RPC::Service.new(
      framework,
      users: [
        ['user', 'password']
      ]
    )
  end
  let(:database) { double('database', active: false) }

  subject(:rpc_auth) { described_class.new(service) }

  before do
    allow(framework).to receive(:db).and_return(database)
  end

  describe '#rpc_login_noauth' do
    it 'creates an authenticated temporary token for valid in-memory credentials' do
      result = rpc_auth.rpc_login_noauth('user', 'password')

      expect(result['result']).to eq('success')
      expect(service.authenticate(result['token'])).to be(true)
    end

    it 'rejects invalid credentials without creating a token' do
      allow(IO).to receive(:select).and_return(nil)

      expect { rpc_auth.rpc_login_noauth('user', 'wrong-password') }
        .to raise_error(Msf::RPC::Exception) { |error| expect(error.code).to eq(401) }
      expect(service.tokens).to be_empty
    end
  end

  describe '#rpc_logout' do
    it 'invalidates a temporary login token' do
      token = rpc_auth.rpc_login_noauth('user', 'password').fetch('token')

      expect(rpc_auth.rpc_logout(token)).to eq('result' => 'success')
      expect(service.authenticate(token)).to be(false)
    end

    it 'rejects an unknown token without changing existing tokens' do
      service.add_token('permanent-token')

      expect { rpc_auth.rpc_logout('unknown-token') }
        .to raise_error(Msf::RPC::Exception) { |error| expect(error.code.to_i).to eq(500) }
      expect(service.authenticate('permanent-token')).to be(true)
    end

    it 'rejects a permanent token without removing it' do
      service.add_token('permanent-token')

      expect { rpc_auth.rpc_logout('permanent-token') }
        .to raise_error(Msf::RPC::Exception) { |error| expect(error.code.to_i).to eq(500) }
      expect(service.authenticate('permanent-token')).to be(true)
    end
  end

  describe 'token administration' do
    it 'adds, lists, and removes an in-memory token' do
      expect(rpc_auth.rpc_token_add('managed-token')).to eq('result' => 'success')
      expect(rpc_auth.rpc_token_list.fetch('tokens')).to include('managed-token')
      expect(service.authenticate('managed-token')).to be(true)

      expect(rpc_auth.rpc_token_remove('managed-token')).to eq('result' => 'success')
      expect(rpc_auth.rpc_token_list.fetch('tokens')).not_to include('managed-token')
      expect(service.authenticate('managed-token')).to be(false)
    end

    it 'generates an authenticated in-memory token' do
      result = rpc_auth.rpc_token_generate

      expect(result['result']).to eq('success')
      expect(service.authenticate(result['token'])).to be(true)
    end
  end
end
