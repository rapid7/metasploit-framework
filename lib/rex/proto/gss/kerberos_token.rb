# frozen_string_literal: true

require 'rex/proto/gss'
require 'rex/proto/gss/asn1'
require 'rex/proto/gss/spnego_neg_token_init'
require 'rex/proto/gss/spnego_neg_token_targ'

module Rex
  module Proto
    module Gss
      # Represents the RFC 1964 framing around an opaque Kerberos protocol
      # message and provides the RFC 4178 SPNEGO operations needed to carry it.
      #
      # The Kerberos message payload is deliberately not decoded. In particular,
      # AP-REQ bytes can be extracted and rebuilt without changing the encrypted
      # ticket or authenticator.
      class KerberosToken
        extend Rex::Proto::Gss::Asn1

        # Raised when a GSS or SPNEGO token cannot be parsed or does not satisfy
        # the requested Kerberos token constraints.
        class ParseError < StandardError; end

        # RFC 1964 section 1.1 token identifiers.
        # @see https://datatracker.ietf.org/doc/html/rfc1964#section-1.1
        TOK_ID_KRB_AP_REQ = "\x01\x00".b
        TOK_ID_KRB_AP_REP = "\x02\x00".b
        TOK_ID_KRB_ERROR = "\x03\x00".b

        KERBEROS_MECHANISM_OIDS = [
          Rex::Proto::Gss::OID_KERBEROS_5.value,
          Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5.value
        ].freeze

        # @return [String] the GSS mechanism OID
        attr_reader :mechanism_oid

        # @return [String] the two-byte RFC 1964 token identifier
        attr_reader :token_id

        # @return [String] the opaque Kerberos message payload
        attr_reader :payload

        # @param mechanism_oid [String]
        # @param token_id [String]
        # @param payload [String]
        def initialize(mechanism_oid:, token_id:, payload:)
          @mechanism_oid = mechanism_oid
          @token_id = token_id
          @payload = payload
        end

        # Parses a bare GSS-Kerberos token and validates its mechanism OID.
        #
        # @param token [String, #to_binary_s]
        # @return [KerberosToken]
        # @raise [ParseError] if the token is malformed or is not a supported
        #   Kerberos mechanism
        def self.parse(token)
          blob = binary_string(token)
          mechanism, encapsulated_token = unwrap_pseudo_asn1(blob)
          parse_unwrapped(mechanism, encapsulated_token)
        rescue ParseError
          raise
        rescue OpenSSL::ASN1::ASN1Error, TypeError => e
          raise ParseError, "unable to parse GSS-Kerberos token: #{e.message}"
        end

        # Parses an RFC 4178 SPNEGO NegTokenInit.
        #
        # @param token [String, #to_binary_s]
        # @return [Hash] SPNEGO mechanism and optimistic-token metadata
        # @raise [ParseError] if the token is malformed or does not use the
        #   SPNEGO mechanism OID
        def self.parse_spnego_init(token)
          spnego = Rex::Proto::Gss::SpnegoNegTokenInit.parse(binary_string(token))
          mechanism_oid = spnego[:gssapi][:oid].value
          unless mechanism_oid == Rex::Proto::Gss::OID_SPNEGO.value
            raise ParseError, "unsupported GSS mechanism OID #{mechanism_oid.inspect}"
          end

          mech_types = []
          index = 0
          while (mech_type = spnego.mech_type_list[index])
            mech_types << mech_type.value
            index += 1
          end
          if mech_types.empty?
            raise ParseError, 'SPNEGO NegTokenInit requires at least one mechanism type'
          end

          neg_token_init = spnego[:gssapi][:neg_token_init]
          {
            mechanism_oid: mechanism_oid,
            mech_types: mech_types,
            preferred_mech: mech_types.first,
            req_flags: neg_token_init[:context_flags]&.value,
            mech_token: spnego.mech_token,
            mech_list_mic: neg_token_init[:mech_list_mic]&.value
          }.compact
        rescue ParseError
          raise
        rescue RASN1::Error, TypeError => e
          raise ParseError, "unable to parse SPNEGO NegTokenInit: #{e.message}"
        end

        # Parses an RFC 4178 SPNEGO NegTokenResp.
        #
        # @param token [String, #to_binary_s]
        # @return [Hash] SPNEGO negotiation result and response-token metadata
        # @raise [ParseError] if the token is malformed
        def self.parse_spnego_response(token)
          spnego = Rex::Proto::Gss::SpnegoNegTokenTarg.parse(binary_string(token))
          {
            neg_state: spnego_neg_state_name(spnego.neg_result),
            supported_mech: spnego.supported_mech,
            response_token: spnego.response_token,
            mech_list_mic: spnego.mech_list_mic
          }.compact
        rescue ParseError
          raise
        rescue RASN1::Error, TypeError => e
          raise ParseError, "unable to parse SPNEGO NegTokenResp: #{e.message}"
        end

        # Extracts an opaque AP-REQ from a bare GSS-Kerberos token or an RFC
        # 4178 SPNEGO NegTokenInit.
        #
        # @param token [String, #to_binary_s]
        # @return [String] the byte-identical AP-REQ payload
        # @raise [ParseError] if the token is not a Kerberos AP-REQ
        def self.extract_ap_req(token)
          blob = binary_string(token)
          mechanism, encapsulated_token = unwrap_pseudo_asn1(blob)

          kerberos_token = if mechanism.value == Rex::Proto::Gss::OID_SPNEGO.value
                             spnego = parse_spnego_init(blob)
                             mech_token = spnego[:mech_token]
                             raise ParseError, 'SPNEGO NegTokenInit does not contain a mechanism token' if mech_token.nil?
                             raise ParseError, 'SPNEGO mechanism token must not be empty' if mech_token.empty?

                             begin
                               parse(mech_token)
                             rescue ParseError => e
                               raise ParseError, "SPNEGO mechanism token is not a valid Kerberos token: #{e.message}"
                             end
                           else
                             parse_unwrapped(mechanism, encapsulated_token)
                           end

          unless kerberos_token.ap_req?
            raise ParseError, "GSS-Kerberos token is not an AP-REQ (token ID #{kerberos_token.token_id_hex})"
          end
          if kerberos_token.payload.empty?
            raise ParseError, 'GSS-Kerberos AP-REQ payload is empty'
          end

          kerberos_token.payload
        rescue ParseError
          raise
        rescue OpenSSL::ASN1::ASN1Error, TypeError => e
          raise ParseError, "unable to extract Kerberos AP-REQ: #{e.message}"
        end

        # Attempts to extract an AP-REQ without raising for an unsupported or
        # malformed token. This is useful when dispatching between GSS
        # mechanisms, such as Kerberos and NTLM.
        #
        # @param token [String, #to_binary_s]
        # @return [String, nil] the opaque AP-REQ payload, or nil
        def self.try_extract_ap_req(token)
          extract_ap_req(token)
        rescue ParseError
          nil
        end

        # Tests whether a GSS or SPNEGO token contains a Kerberos AP-REQ.
        #
        # @param token [String, #to_binary_s]
        # @return [Boolean]
        def self.kerberos_ap_req?(token)
          !try_extract_ap_req(token).nil?
        end

        # Builds an RFC 1964 GSS-Kerberos token containing an opaque AP-REQ.
        #
        # @param ap_req_der [String, #to_binary_s] encoded AP-REQ bytes
        # @param mechanism_oid [OpenSSL::ASN1::ObjectId, String] the Kerberos
        #   mechanism OID placed in the GSS wrapper
        # @return [String]
        def self.build_gss_ap_req(ap_req_der, mechanism_oid: Rex::Proto::Gss::OID_KERBEROS_5)
          mechanism = asn1_object_id(mechanism_oid)
          validate_kerberos_mechanism!(mechanism.value)
          ap_req_der = required_binary_string(ap_req_der, 'AP-REQ')
          wrap_pseudo_asn1(mechanism, TOK_ID_KRB_AP_REQ + ap_req_der)
        end

        # Builds an RFC 4178 SPNEGO NegTokenInit around an existing mechanism
        # token.
        #
        # @param mech_token [String, #to_binary_s]
        # @param mech_types [Array<OpenSSL::ASN1::ObjectId, String>] ordered
        #   initiator mechanism preferences
        # @return [String]
        def self.build_spnego_init(mech_token, mech_types: [Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5])
          encoded_mech_types = mech_types.map { |mechanism| asn1_object_id(mechanism) }
          if encoded_mech_types.empty?
            raise ParseError, 'SPNEGO NegTokenInit requires at least one mechanism type'
          end

          mech_token = required_binary_string(mech_token, 'SPNEGO mechanism token')

          OpenSSL::ASN1::ASN1Data.new([
            Rex::Proto::Gss::OID_SPNEGO,
            OpenSSL::ASN1::ASN1Data.new([
              OpenSSL::ASN1::Sequence.new([
                OpenSSL::ASN1::ASN1Data.new([
                  OpenSSL::ASN1::Sequence.new(encoded_mech_types)
                ], 0, :CONTEXT_SPECIFIC),
                OpenSSL::ASN1::ASN1Data.new([
                  OpenSSL::ASN1::OctetString.new(mech_token)
                ], 2, :CONTEXT_SPECIFIC)
              ])
            ], 0, :CONTEXT_SPECIFIC)
          ], 0, :APPLICATION).to_der
        end

        # Builds an RFC 4178 SPNEGO NegTokenInit containing a GSS-Kerberos
        # AP-REQ. The AP-REQ payload is never decoded or modified.
        #
        # @param ap_req_der [String, #to_binary_s]
        # @return [String]
        def self.build_spnego_ap_req(ap_req_der)
          build_spnego_init(build_gss_ap_req(ap_req_der))
        end

        # Coerces protocol binary fields into binary strings.
        #
        # @param value [String, #to_binary_s, #to_s]
        # @return [String, nil]
        # @raise [ParseError] if the value cannot be represented as bytes
        def self.binary_string(value)
          return nil if value.nil?

          result = if value.is_a?(String)
                     value
                   elsif value.respond_to?(:to_binary_s)
                     value.to_binary_s
                   elsif value.respond_to?(:bytesize) && value.respond_to?(:to_s)
                     value.to_s
                   end

          unless result.is_a?(String)
            raise ParseError, "value of type #{value.class} cannot be converted to a binary string"
          end

          result.b
        end

        # @return [String] hexadecimal token identifier
        def token_id_hex
          token_id.unpack1('H*')
        end

        # @return [String] readable Kerberos token type
        def token_type
          case token_id
          when TOK_ID_KRB_AP_REQ
            'AP-REQ'
          when TOK_ID_KRB_AP_REP
            'AP-REP'
          when TOK_ID_KRB_ERROR
            'KRB-ERROR'
          else
            "UNKNOWN (#{token_id_hex})"
          end
        end

        # @return [Boolean] whether this token contains an AP-REQ
        def ap_req?
          token_id == TOK_ID_KRB_AP_REQ
        end

        class << self
          private

          def parse_unwrapped(mechanism, encapsulated_token)
            unless mechanism.respond_to?(:value)
              raise ParseError, 'GSS token does not contain a mechanism OID'
            end

            mechanism_oid = mechanism.value
            validate_kerberos_mechanism!(mechanism_oid)
            if encapsulated_token.nil? || encapsulated_token.bytesize < 2
              raise ParseError, 'GSS-Kerberos token does not contain a two-byte token ID'
            end

            new(
              mechanism_oid: mechanism_oid,
              token_id: encapsulated_token.byteslice(0, 2),
              payload: encapsulated_token.byteslice(2, encapsulated_token.bytesize - 2)
            )
          end

          def validate_kerberos_mechanism!(mechanism_oid)
            return if KERBEROS_MECHANISM_OIDS.include?(mechanism_oid)

            raise ParseError, "unsupported Kerberos mechanism OID #{mechanism_oid.inspect}"
          end

          def asn1_object_id(value)
            return value if value.is_a?(OpenSSL::ASN1::ObjectId)

            OpenSSL::ASN1::ObjectId.new(value.to_s)
          rescue OpenSSL::ASN1::ASN1Error, TypeError => e
            raise ParseError, "invalid mechanism OID: #{e.message}"
          end

          def required_binary_string(value, label)
            value = binary_string(value)
            raise ParseError, "#{label} must not be empty" if value.nil? || value.empty?

            value
          end

          def spnego_neg_state_name(value)
            return nil if value.nil?
            return value if Rex::Proto::Gss::SpnegoNegTokenTarg::NEG_RESULTS.key?(value)

            Rex::Proto::Gss::SpnegoNegTokenTarg::NEG_RESULTS.invert.fetch(value, "unknown (#{value})")
          end
        end
      end
    end
  end
end
