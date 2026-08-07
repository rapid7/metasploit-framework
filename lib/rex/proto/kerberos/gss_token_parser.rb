# frozen_string_literal: true

require 'rex/proto/gss/kerberos_token'

module Rex
  module Proto
    module Kerberos
      # Parses GSS-Kerberos and SPNEGO tokens for trace presentation.
      class GssTokenParser
        # Parses the GSS-Kerberos framing defined by RFC 1964 section 1.1.
        #
        # @param token [String, #to_binary_s]
        # @return [Hash]
        # @see https://datatracker.ietf.org/doc/html/rfc1964#section-1.1
        def parse_kerberos(token)
          parsed = Rex::Proto::Gss::KerberosToken.parse(token)

          compact_hash(
            mechanism_oid: parsed.mechanism_oid,
            token_id: parsed.token_id_hex,
            inner_token_type: parsed.token_type,
            ap_req_payload: parsed.ap_req? ? parsed.payload : nil,
            response_payload: parsed.ap_req? ? nil : parsed.payload
          )
        rescue Rex::Proto::Gss::KerberosToken::ParseError => e
          { parse_failure: "unable to parse token as GSS-Kerberos: #{e.class}: #{e.message}" }
        end

        # Parses a SPNEGO NegTokenInit token defined by RFC 4178 section 4.2.1.
        #
        # @param token [String, #to_binary_s]
        # @return [Hash]
        # @see https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.1
        def parse_spnego_init(token)
          Rex::Proto::Gss::KerberosToken.parse_spnego_init(token)
        rescue Rex::Proto::Gss::KerberosToken::ParseError => e
          { parse_failure: "unable to parse token as SPNEGO NegTokenInit: #{e.class}: #{e.message}" }
        end

        # Parses a SPNEGO NegTokenResp token defined by RFC 4178 section 4.2.2.
        #
        # @param token [String, #to_binary_s]
        # @return [Hash]
        # @see https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.2
        def parse_spnego_response(token)
          Rex::Proto::Gss::KerberosToken.parse_spnego_response(token)
        rescue Rex::Proto::Gss::KerberosToken::ParseError => e
          { parse_failure: "unable to parse response token as SPNEGO NegTokenResp: #{e.class}: #{e.message}" }
        end

        # Coerces string-like protocol fields to binary strings.
        #
        # @param value [Object]
        # @return [String, nil, Object]
        def binary_string(value)
          Rex::Proto::Gss::KerberosToken.binary_string(value)
        end

        private

        def compact_hash(hash)
          hash.compact
        end
      end
    end
  end
end
