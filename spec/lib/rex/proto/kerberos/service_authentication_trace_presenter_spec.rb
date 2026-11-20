# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/kerberos/service_authentication_trace_presenter'

RSpec.describe Rex::Proto::Kerberos::ServiceAuthenticationTracePresenter do
  subject(:presenter) { described_class.new(trace_mode: trace_mode) }

  let(:trace_mode) { 'metadata' }
  let(:ap_req_der) { "\x6e\x03\x02\x01\x05".b }
  let(:gss_token) do
    OpenSSL::ASN1::ASN1Data.new(
      [Rex::Proto::Gss::OID_KERBEROS_5, "\x01\x00".b + ap_req_der],
      0,
      :APPLICATION
    ).to_der
  end

  describe '#present_ap_req' do
    it 'presents service-authentication metadata without a logger dependency' do
      output = presenter.present_ap_req(
        service_principal: 'cifs/server.example@EXAMPLE',
        realm: 'EXAMPLE',
        mutual_auth: true,
        use_subkey: false
      )

      expect(output).to include('Message Type: 14 (AP-REQ)')
      expect(output).to include('Service Principal: cifs/server.example@EXAMPLE')
      expect(output).to include('Mutual Authentication: requested')
    end
  end

  describe '#present_gss_token' do
    it 'presents the parsed GSS-Kerberos wrapper' do
      output = presenter.present_gss_token(token: gss_token, ap_req_der: ap_req_der)

      expect(output).to include('Wrapper Type: GSS-Kerberos')
      expect(output).to include('Inner Token Type: AP-REQ')
      expect(output).to include('AP-REQ Payload Matches: true')
    end
  end

  describe '#present_spnego_token' do
    it 'turns parser failures into trace output' do
      output = presenter.present_spnego_token(token: 'not-spnego')

      expect(output).to include('Wrapper Type: SPNEGO NegTokenInit')
      expect(output).to include('Parse Failure: unable to parse token as SPNEGO NegTokenInit')
    end

    it 'labels the initiator first mechanism as preferred rather than selected' do
      output = presenter.present_spnego_token(
        token: OpenSSL::ASN1::ASN1Data.new(
          [
            Rex::Proto::Gss::OID_SPNEGO,
            OpenSSL::ASN1::ASN1Data.new(
              [
                OpenSSL::ASN1::Sequence.new(
                  [
                    OpenSSL::ASN1::ASN1Data.new(
                      [OpenSSL::ASN1::Sequence.new([Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5])],
                      0,
                      :CONTEXT_SPECIFIC
                    )
                  ]
                )
              ],
              0,
              :CONTEXT_SPECIFIC
            )
          ],
          0,
          :APPLICATION
        ).to_der
      )

      expect(output).to include('Preferred Mech: 1.2.840.48018.1.2.2')
      expect(output).not_to include('Selected Mech:')
    end
  end

  describe '#present_response_token' do
    it 'presents malformed inbound tokens without raising' do
      output = presenter.present_response_token(token_type: 'GSS-Kerberos', token: 'not-asn1')

      expect(output).to include('Direction: inbound')
      expect(output).to include('Parse Failure: unable to parse response token as AP-REP/KRB-ERROR/SPNEGO')
    end

    it 'does not treat a requested mutual-auth exchange as successful without a result' do
      output = presenter.present_response_token(
        token_type: 'GSS-Kerberos',
        token: 'not-asn1',
        mutual_auth: true
      )

      expect(output).not_to include('Mutual Authentication: success')
    end

    it 'presents an explicit mutual-auth failure result' do
      output = presenter.present_response_token(
        token_type: 'GSS-Kerberos',
        token: 'not-asn1',
        mutual_auth: true,
        mutual_authentication: 'failed'
      )

      expect(output).to include('Mutual Authentication: failed')
      expect(output).not_to include('Mutual Authentication: success')
    end
  end

  context 'when trace mode is full' do
    let(:trace_mode) { 'full' }

    it 'includes binary token contents' do
      expect(presenter.present_gss_token(token: gss_token)).to include(gss_token.unpack1('H*'))
    end
  end
end
