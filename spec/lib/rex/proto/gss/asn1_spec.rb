# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/gss/asn1'

RSpec.describe Rex::Proto::Gss::Asn1 do
  subject(:asn1_helper) do
    Class.new do
      include Rex::Proto::Gss::Asn1
    end.new
  end

  describe '#unwrap_pseudo_asn1' do
    it 'returns the mechanism OID and opaque token bytes' do
      payload = "\x01\x00opaque-token".b
      wrapped = asn1_helper.wrap_pseudo_asn1(Rex::Proto::Gss::OID_KERBEROS_5, payload)

      mechanism, token = asn1_helper.unwrap_pseudo_asn1(wrapped)

      expect(mechanism.value).to eq(Rex::Proto::Gss::OID_KERBEROS_5.value)
      expect(token).to eq(payload)
    end

    it 'raises an ASN.1 error instead of TypeError when no top-level mechanism OID is present' do
      neg_token_response = OpenSSL::ASN1::ASN1Data.new(
        [OpenSSL::ASN1::Sequence.new([])],
        1,
        :CONTEXT_SPECIFIC
      ).to_der

      expect { asn1_helper.unwrap_pseudo_asn1(neg_token_response) }.to raise_error(
        OpenSSL::ASN1::ASN1Error,
        /does not contain a top-level mechanism OID/
      )
    end

    it 'preserves the ASN.1 error for malformed input' do
      expect { asn1_helper.unwrap_pseudo_asn1('not-asn1') }.to raise_error(OpenSSL::ASN1::ASN1Error)
    end
  end
end
