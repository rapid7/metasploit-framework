require 'spec_helper'
require 'rex/proto/ldap/auth_adapter/rex_ntlm'

RSpec.describe Rex::Proto::LDAP::AuthAdapter::RexNTLM do
  describe '.create_ntlm_client' do
    it 'builds an anonymous SASL identity with signing and sealing' do
      client = described_class.create_ntlm_client(username: '', password: '', domain: '', sign_and_seal: true, anonymous_sasl: true)

      expect(client.username).to be_empty
      expect(client.password).to be_empty
      expect(client.domain).to be_empty
      expect(client.workstation).to be_empty
      expect(client.flags & RubySMB::NTLM::NEGOTIATE_FLAGS[:SIGN]).not_to be_zero
      expect(client.flags & RubySMB::NTLM::NEGOTIATE_FLAGS[:SEAL]).not_to be_zero
      expect(client.flags & RubySMB::NTLM::NEGOTIATE_FLAGS[:VERSION_INFO]).to be_zero
      expect(client.init_context.serialize.bytesize).to eq(32)
    end

    it 'preserves ordinary empty-credential client behavior without the anonymous SASL option' do
      client = described_class.create_ntlm_client(username: '', password: '', domain: '', sign_and_seal: true)

      expect(client.domain).to eq('.')
      expect(client.workstation).to eq('WORKSTATION')
      expect(client.flags & RubySMB::NTLM::NEGOTIATE_FLAGS[:VERSION_INFO]).not_to be_zero
    end
  end
end
