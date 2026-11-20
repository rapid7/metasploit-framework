# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/kerberos/gss_token_parser'

RSpec.describe Rex::Proto::Kerberos::GssTokenParser do
  subject(:parser) { described_class.new }

  let(:ap_req_der) { "\x6e\x03\x02\x01\x05".b }
  let(:gss_token) { build_gss_kerberos_token(ap_req_der) }
  let(:spnego_init) { build_spnego_neg_token_init(gss_token) }
  let(:spnego_response) do
    "\xa1\x14\x30\x12\xa0\x03\x0a\x01\x00\xa1\x0b\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02".b
  end

  describe '#parse_kerberos' do
    it 'extracts the mechanism, token type, and AP-REQ payload' do
      result = parser.parse_kerberos(gss_token)

      expect(result).to include(
        mechanism_oid: Rex::Proto::Gss::OID_KERBEROS_5.value,
        token_id: '0100',
        inner_token_type: 'AP-REQ',
        ap_req_payload: ap_req_der
      )
    end

    it 'returns a parse failure instead of raising for malformed input' do
      expect(parser.parse_kerberos('not-asn1')).to include(parse_failure: match(/GSS-Kerberos/))
    end

    it 'accepts the Microsoft Kerberos mechanism OID' do
      token = Rex::Proto::Gss::KerberosToken.build_gss_ap_req(
        ap_req_der,
        mechanism_oid: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5
      )

      expect(parser.parse_kerberos(token)).to include(
        mechanism_oid: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value,
        inner_token_type: 'AP-REQ'
      )
    end

    it 'turns unsupported mechanisms into a trace parse failure' do
      token = OpenSSL::ASN1::ASN1Data.new(
        [
          OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.2.2.10'),
          "\x01\x00".b + ap_req_der
        ],
        0,
        :APPLICATION
      ).to_der

      expect(parser.parse_kerberos(token)).to include(
        parse_failure: match(/unsupported Kerberos mechanism OID/)
      )
    end

    it 'does not hide unexpected programming errors' do
      allow(Rex::Proto::Gss::KerberosToken).to receive(:parse).and_raise(RuntimeError, 'unexpected bug')

      expect { parser.parse_kerberos(gss_token) }.to raise_error(RuntimeError, 'unexpected bug')
    end
  end

  describe '#parse_spnego_init' do
    it 'extracts the offered mechanism and optimistic mechanism token' do
      result = parser.parse_spnego_init(spnego_init)

      expect(result).to include(
        mech_types: [Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value],
        preferred_mech: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value,
        mech_token: gss_token
      )
    end
  end

  describe '#parse_spnego_response' do
    it 'extracts the negotiation state and selected mechanism' do
      expect(parser.parse_spnego_response(spnego_response)).to include(
        neg_state: Rex::Proto::Gss::SpnegoNegTokenTarg::ACCEPT_COMPLETED,
        supported_mech: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value
      )
    end
  end

  describe '#binary_string' do
    it 'coerces protocol binary objects' do
      token = double('binary token', to_binary_s: gss_token)

      expect(parser.binary_string(token)).to eq(gss_token)
    end
  end

  def build_gss_kerberos_token(payload)
    OpenSSL::ASN1::ASN1Data.new(
      [Rex::Proto::Gss::OID_KERBEROS_5, "\x01\x00".b + payload],
      0,
      :APPLICATION
    ).to_der
  end

  def build_spnego_neg_token_init(token)
    OpenSSL::ASN1::ASN1Data.new(
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
                ),
                OpenSSL::ASN1::ASN1Data.new(
                  [OpenSSL::ASN1::OctetString.new(token)],
                  2,
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
  end
end
