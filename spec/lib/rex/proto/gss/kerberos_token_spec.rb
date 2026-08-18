# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/gss/kerberos_token'

RSpec.describe Rex::Proto::Gss::KerberosToken do
  let(:ap_req_der) do
    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::OctetString.new('AP-REQ-PAYLOAD')
    ]).to_der
  end
  let(:ap_rep_der) do
    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::OctetString.new('AP-REP-PAYLOAD')
    ]).to_der
  end
  let(:gss_ap_req) do
    described_class.build_gss_ap_req(ap_req_der)
  end
  let(:spnego_ap_req) do
    described_class.build_spnego_ap_req(ap_req_der)
  end
  let(:spnego_response) do
    "\xa1\x14\x30\x12\xa0\x03\x0a\x01\x00\xa1\x0b\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02".b
  end

  describe '.parse' do
    it 'parses the standard Kerberos mechanism and preserves the opaque AP-REQ payload' do
      token = described_class.parse(gss_ap_req)

      expect(token.mechanism_oid).to eq(Rex::Proto::Gss::OID_KERBEROS_5.value)
      expect(token.token_id).to eq(described_class::TOK_ID_KRB_AP_REQ)
      expect(token.token_id_hex).to eq('0100')
      expect(token.token_type).to eq('AP-REQ')
      expect(token.payload).to eq(ap_req_der)
      expect(token).to be_ap_req
    end

    it 'accepts the Microsoft Kerberos mechanism OID' do
      gss_token = described_class.build_gss_ap_req(
        ap_req_der,
        mechanism_oid: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5
      )

      expect(described_class.parse(gss_token).mechanism_oid).to eq(
        Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value
      )
    end

    it 'identifies AP-REP and unknown token IDs without decoding their payloads' do
      ap_rep = described_class.parse(
        gss_token(described_class::TOK_ID_KRB_AP_REP, ap_rep_der)
      )
      unknown = described_class.parse(gss_token("\xff\xff".b, 'unknown'))

      expect(ap_rep.token_type).to eq('AP-REP')
      expect(ap_rep.payload).to eq(ap_rep_der)
      expect(unknown.token_type).to eq('UNKNOWN (ffff)')
      expect(unknown.payload).to eq('unknown')
    end

    it 'rejects a non-Kerberos mechanism OID' do
      token = gss_token(
        described_class::TOK_ID_KRB_AP_REQ,
        ap_req_der,
        mechanism_oid: OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.2.2.10')
      )

      expect { described_class.parse(token) }.to raise_error(
        described_class::ParseError,
        /unsupported Kerberos mechanism OID/
      )
    end

    it 'normalizes malformed input into ParseError' do
      expect { described_class.parse('not-asn1') }.to raise_error(
        described_class::ParseError,
        /unable to parse GSS-Kerberos token/
      )
    end

    it 'rejects a GSS-Kerberos token without a complete token ID' do
      token = gss_token("\x01".b, '')

      expect { described_class.parse(token) }.to raise_error(
        described_class::ParseError,
        /does not contain a two-byte token ID/
      )
    end
  end

  describe '.parse_spnego_init' do
    it 'returns the ordered mechanism preferences and optimistic mechanism token' do
      parsed = described_class.parse_spnego_init(spnego_ap_req)

      expect(parsed).to include(
        mechanism_oid: Rex::Proto::Gss::OID_SPNEGO.value,
        mech_types: [Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value],
        preferred_mech: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value,
        mech_token: gss_ap_req
      )
      expect(parsed).not_to include(:selected_mech)
    end

    it 'preserves the initiator mechanism preference order' do
      ntlm_oid = OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.2.2.10')
      token = described_class.build_spnego_init(
        gss_ap_req,
        mech_types: [ntlm_oid, Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5]
      )

      expect(described_class.parse_spnego_init(token)).to include(
        mech_types: [ntlm_oid.value, Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value],
        preferred_mech: ntlm_oid.value
      )
    end

    it 'rejects an empty mechanism list' do
      token = spnego_init_token(mech_types: [], mech_token: gss_ap_req)

      expect { described_class.parse_spnego_init(token) }.to raise_error(
        described_class::ParseError,
        /requires at least one mechanism type/
      )
    end

    it 'normalizes malformed input into ParseError' do
      expect { described_class.parse_spnego_init('not-spnego') }.to raise_error(
        described_class::ParseError,
        /unable to parse SPNEGO NegTokenInit/
      )
    end
  end

  describe '.parse_spnego_response' do
    it 'returns the negotiation state and selected mechanism' do
      expect(described_class.parse_spnego_response(spnego_response)).to include(
        neg_state: Rex::Proto::Gss::SpnegoNegTokenTarg::ACCEPT_COMPLETED,
        supported_mech: Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value
      )
    end

    it 'normalizes malformed input into ParseError' do
      expect { described_class.parse_spnego_response('not-spnego') }.to raise_error(
        described_class::ParseError,
        /unable to parse SPNEGO NegTokenResp/
      )
    end
    it 'normalizes an out-of-range neg_result into ParseError instead of leaking RASN1::EnumeratedError' do
      token = OpenSSL::ASN1::ASN1Data.new(
        [
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Enumerated.new(99)], 0, :CONTEXT_SPECIFIC)
          ])
        ],
        1,
        :CONTEXT_SPECIFIC
      ).to_der

      expect { described_class.parse_spnego_response(token) }.to raise_error(
        described_class::ParseError,
        /unable to parse SPNEGO NegTokenResp/
      )
    end
  end

  describe '.extract_ap_req' do
    it 'extracts a byte-identical AP-REQ from bare GSS and SPNEGO tokens' do
      expect(described_class.extract_ap_req(gss_ap_req)).to eq(ap_req_der)
      expect(described_class.extract_ap_req(spnego_ap_req)).to eq(ap_req_der)
    end

    it 'rejects a Kerberos token that is not an AP-REQ' do
      token = gss_token(described_class::TOK_ID_KRB_AP_REP, ap_rep_der)

      expect { described_class.extract_ap_req(token) }.to raise_error(
        described_class::ParseError,
        /is not an AP-REQ/
      )
    end

    it 'rejects a SPNEGO token containing a non-Kerberos mechanism token' do
      token = described_class.build_spnego_init("NTLMSSP\x00\x01".b)

      expect { described_class.extract_ap_req(token) }.to raise_error(
        described_class::ParseError,
        /SPNEGO mechanism token is not a valid Kerberos token/
      )
    end

    it 'rejects an empty SPNEGO mechanism token' do
      token = spnego_init_token(
        mech_types: [Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5],
        mech_token: ''
      )

      expect { described_class.extract_ap_req(token) }.to raise_error(
        described_class::ParseError,
        /SPNEGO mechanism token must not be empty/
      )
    end

    it 'rejects a SPNEGO NegTokenResp without leaking TypeError' do
      expect { described_class.extract_ap_req(spnego_response) }.to raise_error(
        described_class::ParseError,
        /unable to extract Kerberos AP-REQ/
      )
    end

    it 'rejects an empty AP-REQ payload' do
      token = gss_token(described_class::TOK_ID_KRB_AP_REQ, '')

      expect { described_class.extract_ap_req(token) }.to raise_error(
        described_class::ParseError,
        /AP-REQ payload is empty/
      )
    end
  end

  describe '.try_extract_ap_req' do
    it 'returns the AP-REQ for a supported token' do
      expect(described_class.try_extract_ap_req(spnego_ap_req)).to eq(ap_req_der)
    end

    it 'returns nil for malformed input and other GSS mechanisms' do
      ntlm = described_class.build_spnego_init("NTLMSSP\x00\x01".b)

      expect(described_class.try_extract_ap_req('not-asn1')).to be_nil
      expect(described_class.try_extract_ap_req(ntlm)).to be_nil
      expect(described_class.try_extract_ap_req(spnego_response)).to be_nil
    end
  end

  describe '.kerberos_ap_req?' do
    it 'distinguishes Kerberos AP-REQ tokens from other input' do
      expect(described_class.kerberos_ap_req?(gss_ap_req)).to be(true)
      expect(described_class.kerberos_ap_req?(spnego_ap_req)).to be(true)
      expect(described_class.kerberos_ap_req?('not-asn1')).to be(false)
    end
  end

  describe 'AP-REQ builders' do
    it 'round-trips AP-REQ bytes through the GSS-Kerberos builder' do
      expect(described_class.parse(gss_ap_req).payload).to eq(ap_req_der)
    end

    it 'round-trips AP-REQ bytes through the SPNEGO builder' do
      expect(described_class.extract_ap_req(spnego_ap_req)).to eq(ap_req_der)
    end

    it 'rejects an empty SPNEGO mechanism list' do
      expect { described_class.build_spnego_init(gss_ap_req, mech_types: []) }.to raise_error(
        described_class::ParseError,
        /requires at least one mechanism type/
      )
    end

    it 'rejects empty AP-REQ and mechanism-token inputs' do
      expect { described_class.build_gss_ap_req(nil) }.to raise_error(
        described_class::ParseError,
        /AP-REQ must not be empty/
      )
      expect { described_class.build_spnego_init('') }.to raise_error(
        described_class::ParseError,
        /SPNEGO mechanism token must not be empty/
      )
    end
  end

  describe '.binary_string' do
    it 'coerces protocol binary objects' do
      value = double('binary value', to_binary_s: ap_req_der)

      expect(described_class.binary_string(value)).to eq(ap_req_der)
    end

    it 'rejects values that cannot be represented as bytes' do
      expect { described_class.binary_string(Object.new) }.to raise_error(
        described_class::ParseError,
        /cannot be converted to a binary string/
      )
    end
  end

  def gss_token(token_id, payload, mechanism_oid: Rex::Proto::Gss::OID_KERBEROS_5)
    OpenSSL::ASN1::ASN1Data.new(
      [mechanism_oid, token_id + payload],
      0,
      :APPLICATION
    ).to_der
  end

  def spnego_init_token(mech_types:, mech_token:)
    OpenSSL::ASN1::ASN1Data.new([
      Rex::Proto::Gss::OID_SPNEGO,
      OpenSSL::ASN1::ASN1Data.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ASN1Data.new([
            OpenSSL::ASN1::Sequence.new(mech_types)
          ], 0, :CONTEXT_SPECIFIC),
          OpenSSL::ASN1::ASN1Data.new([
            OpenSSL::ASN1::OctetString.new(mech_token)
          ], 2, :CONTEXT_SPECIFIC)
        ])
      ], 0, :CONTEXT_SPECIFIC)
    ], 0, :APPLICATION).to_der
  end
end
