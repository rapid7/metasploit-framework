# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/ldap/auth_adapter/rex_kerberos'

RSpec.describe Rex::Proto::LDAP::AuthAdapter::RexKerberos do
  let(:connection) { double('LDAP connection', socket: Object.new) }
  let(:kerberos_authenticator) do
    instance_double(Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base)
  end
  let(:sasl_adapter) { instance_double(Net::LDAP::AuthAdapter::Sasl) }

  subject(:adapter) { described_class.new(connection) }

  describe '#bind' do
    it 'traces the request and response LDAP SASL carriers' do
      request_token = 'request-token'
      response_token = 'response-token'
      result = double('LDAP bind result', result: { serverSaslCreds: response_token })

      allow(kerberos_authenticator).to receive(:authenticate).with({}).and_return(security_blob: request_token)
      allow(kerberos_authenticator).to receive(:trace_protocol_carrier)
      allow(Net::LDAP::AuthAdapter::Sasl).to receive(:new).with(connection).and_return(sasl_adapter)
      allow(sasl_adapter).to receive(:bind).and_return(result)

      expect(adapter.bind(kerberos_authenticator: kerberos_authenticator, sign_and_seal: false)).to eq(result)
      expect(sasl_adapter).to have_received(:bind).with(
        method: :sasl,
        mechanism: 'GSS-SPNEGO',
        initial_credential: request_token,
        challenge_response: true
      )
      expect(kerberos_authenticator).to have_received(:trace_protocol_carrier).with(
        protocol: 'LDAP',
        direction: 'request',
        label: 'LDAP SASL Bind',
        carrier: 'SASL bind request credential',
        field_name: 'initial_credential',
        token: request_token
      )
      expect(kerberos_authenticator).to have_received(:trace_protocol_carrier).with(
        protocol: 'LDAP',
        direction: 'response',
        label: 'LDAP serverSaslCreds',
        carrier: 'SASL bind response serverSaslCreds',
        field_name: 'serverSaslCreds',
        token: response_token
      )
    end
  end
end
