# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    module Kerberos
      module Model
        module Error
          ###
          # This class represents a Kerberos Error Code as defined in:
          # https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
          # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768#table-2-kerberos-ticket-flags)
          ##
          class ErrorCode
            # @return [String] the description of the error the code represents
            attr_reader :description
            # @return [String] the name of the error code
            attr_reader :name
            # @return [Integer] the error code that was given as a return value
            attr_reader :value

            # @param [String] name the 'name' of the error code (i.e KDC_ERR_NONE)
            # @param [Integer] value the return value that represents that error (i.e. 0)
            # @param [String] description the verbose description of the error
            # @raise [ArgumentError] if any of the parameters are of an invalid type
            def initialize(name, value, description)
              raise ArgumentError, 'Invalid Error Name' unless name.is_a?(String) && !name.empty?
              raise ArgumentError, 'Invalid Error Code Value' unless value.is_a?(Integer)
              raise ArgumentError, 'Invalid Error Description' unless description.is_a?(String) && !description.empty?

              @name = name
              @value = value
              @description = description
            end

            # Override the equality test for ErrorCodes. Equality is
            # always tested against the #value of the error code.
            #
            # @param other [Object] The object to test equality against
            # @raise [ArgumentError] if the other object is not either another ErrorCode or a Integer
            # @return [Boolean] whether the equality test passed
            def ==(other)
              if other.is_a? self.class
                value == other.value
              elsif other.is_a? Integer
                value == other
              elsif other.nil?
                false
              else
                raise ArgumentError, "Cannot compare a #{self.class} to a #{other.class}"
              end
            end

            alias === ==

            def to_s
              "#{name} (#{value}) - #{description}"
            end
          end

          # Core Kerberos specification and errors:
          # https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
          # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768#table-2-kerberos-ticket-flags
          #
          # Additional errors added by PKINIT:
          # https://www.rfc-editor.org/rfc/rfc4556#section-3.1.3
          module ErrorCodes
            KDC_ERR_NONE = ErrorCode.new('KDC_ERR_NONE', 0, 'No error')
            KDC_ERR_NAME_EXP = ErrorCode.new('KDC_ERR_NAME_EXP', 1, "Client's entry in database has expired")
            KDC_ERR_SERVICE_EXP = ErrorCode.new('KDC_ERR_SERVICE_EXP', 2, "Server's entry in database has expired")
            KDC_ERR_BAD_PVNO = ErrorCode.new('KDC_ERR_BAD_PVNO', 3, 'Requested protocol version number not supported')
            KDC_ERR_C_OLD_MAST_KVNO = ErrorCode.new('KDC_ERR_C_OLD_MAST_KVNO', 4, "Client's key encrypted in old master key")
            KDC_ERR_S_OLD_MAST_KVNO = ErrorCode.new('KDC_ERR_S_OLD_MAST_KVNO', 5, "Server's key encrypted in old master key")
            KDC_ERR_C_PRINCIPAL_UNKNOWN = ErrorCode.new('KDC_ERR_C_PRINCIPAL_UNKNOWN', 6, 'Client not found in Kerberos database')
            KDC_ERR_S_PRINCIPAL_UNKNOWN = ErrorCode.new('KDC_ERR_S_PRINCIPAL_UNKNOWN', 7, 'Server not found in Kerberos database')
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = ErrorCode.new('KDC_ERR_PRINCIPAL_NOT_UNIQUE', 8, 'Multiple principal entries in database')
            KDC_ERR_NULL_KEY = ErrorCode.new('KDC_ERR_NULL_KEY', 9, 'The client or server has a null key')
            KDC_ERR_CANNOT_POSTDATE = ErrorCode.new('KDC_ERR_CANNOT_POSTDATE', 10, 'Ticket not eligible for postdating')
            KDC_ERR_NEVER_VALID = ErrorCode.new('KDC_ERR_NEVER_VALID', 11, 'Requested start time is later than end time')
            KDC_ERR_POLICY = ErrorCode.new('KDC_ERR_POLICY', 12, 'KDC policy rejects request')
            KDC_ERR_BADOPTION = ErrorCode.new('KDC_ERR_BADOPTION', 13, 'KDC cannot accommodate requested option')
            KDC_ERR_ETYPE_NOSUPP = ErrorCode.new('KDC_ERR_ETYPE_NOSUPP', 14, 'KDC has no support for encryption type')
            KDC_ERR_SUMTYPE_NOSUPP = ErrorCode.new('KDC_ERR_SUMTYPE_NOSUPP', 15, 'KDC has no support for checksum type')
            KDC_ERR_PADATA_TYPE_NOSUPP = ErrorCode.new('KDC_ERR_PADATA_TYPE_NOSUPP', 16, 'KDC has no support for padata type')
            KDC_ERR_TRTYPE_NOSUPP = ErrorCode.new('KDC_ERR_TRTYPE_NOSUPP', 17, 'KDC has no support for transited type')
            KDC_ERR_CLIENT_REVOKED = ErrorCode.new('KDC_ERR_CLIENT_REVOKED', 18, 'Clients credentials have been revoked')
            KDC_ERR_SERVICE_REVOKED = ErrorCode.new('KDC_ERR_SERVICE_REVOKED', 19, 'Credentials for server have been revoked')
            KDC_ERR_TGT_REVOKED = ErrorCode.new('KDC_ERR_TGT_REVOKED', 20, 'TGT has been revoked')
            KDC_ERR_CLIENT_NOTYET = ErrorCode.new('KDC_ERR_CLIENT_NOTYET', 21, 'Client not yet valid - try again later')
            KDC_ERR_SERVICE_NOTYET = ErrorCode.new('KDC_ERR_SERVICE_NOTYET', 22, 'Server not yet valid - try again later')
            KDC_ERR_KEY_EXPIRED = ErrorCode.new('KDC_ERR_KEY_EXPIRED', 23, 'Password has expired - change password to reset')
            KDC_ERR_PREAUTH_FAILED = ErrorCode.new('KDC_ERR_PREAUTH_FAILED', 24, 'Pre-authentication information was invalid')
            KDC_ERR_PREAUTH_REQUIRED = ErrorCode.new('KDC_ERR_PREAUTH_REQUIRED', 25, 'Additional pre-authentication required')
            KDC_ERR_SERVER_NOMATCH = ErrorCode.new('KDC_ERR_SERVER_NOMATCH', 26, "Requested server and ticket don't match")
            KDC_ERR_MUST_USE_USER2USER = ErrorCode.new('KDC_ERR_MUST_USE_USER2USER', 27, 'Server principal valid for user2user only')
            KDC_ERR_PATH_NOT_ACCEPTED = ErrorCode.new('KDC_ERR_PATH_NOT_ACCEPTED', 28, 'KDC Policy rejects transited path')
            KDC_ERR_SVC_UNAVAILABLE = ErrorCode.new('KDC_ERR_SVC_UNAVAILABLE', 29, 'A service is not available')
            KRB_AP_ERR_BAD_INTEGRITY = ErrorCode.new('KRB_AP_ERR_BAD_INTEGRITY', 31, 'Integrity check on decrypted field failed')
            KRB_AP_ERR_TKT_EXPIRED = ErrorCode.new('KRB_AP_ERR_TKT_EXPIRED', 32, 'Ticket expired')
            KRB_AP_ERR_TKT_NYV = ErrorCode.new('KRB_AP_ERR_TKT_NYV', 33, 'Ticket not yet valid')
            KRB_AP_ERR_REPEAT = ErrorCode.new('KRB_AP_ERR_REPEAT', 34, 'Request is a replay')
            KRB_AP_ERR_NOT_US = ErrorCode.new('KRB_AP_ERR_NOT_US', 35, "The ticket isn't for us")
            KRB_AP_ERR_BADMATCH = ErrorCode.new('KRB_AP_ERR_BADMATCH', 36, "Ticket and authenticator don't match")
            KRB_AP_ERR_SKEW = ErrorCode.new('KRB_AP_ERR_SKEW', 37, 'Clock skew too great')
            KRB_AP_ERR_BADADDR = ErrorCode.new('KRB_AP_ERR_BADADDR', 38, 'Incorrect net address')
            KRB_AP_ERR_BADVERSION = ErrorCode.new('KRB_AP_ERR_BADVERSION', 39, 'Protocol version mismatch')
            KRB_AP_ERR_MSG_TYPE = ErrorCode.new('KRB_AP_ERR_MSG_TYPE', 40, 'Invalid msg type')
            KRB_AP_ERR_MODIFIED = ErrorCode.new('KRB_AP_ERR_MODIFIED', 41, 'Message stream modified')
            KRB_AP_ERR_BADORDER = ErrorCode.new('KRB_AP_ERR_BADORDER', 42, 'Message out of order')
            KRB_AP_ERR_BADKEYVER = ErrorCode.new('KRB_AP_ERR_BADKEYVER', 44, 'Specified version of key is not available')
            KRB_AP_ERR_NOKEY = ErrorCode.new('KRB_AP_ERR_NOKEY', 45, 'Service key not available')
            KRB_AP_ERR_MUT_FAIL = ErrorCode.new('KRB_AP_ERR_MUT_FAIL', 46, 'Mutual authentication failed')
            KRB_AP_ERR_BADDIRECTION = ErrorCode.new('KRB_AP_ERR_BADDIRECTION', 47, 'Incorrect message direction')
            KRB_AP_ERR_METHOD = ErrorCode.new('KRB_AP_ERR_METHOD', 48, 'Alternative authentication method required')
            KRB_AP_ERR_BADSEQ = ErrorCode.new('KRB_AP_ERR_BADSEQ', 49, 'Incorrect sequence number in message')
            KRB_AP_ERR_INAPP_CKSUM = ErrorCode.new('KRB_AP_ERR_INAPP_CKSUM', 50, 'Inappropriate type of checksum in message')
            KRB_AP_PATH_NOT_ACCEPTED = ErrorCode.new('KRB_AP_PATH_NOT_ACCEPTED', 51, 'Policy rejects transited path')
            KRB_ERR_RESPONSE_TOO_BIG = ErrorCode.new('KRB_ERR_RESPONSE_TOO_BIG', 52, 'Response too big for UDP; retry with TCP')
            KRB_ERR_GENERIC = ErrorCode.new('KRB_ERR_GENERIC', 60, 'Generic error')
            KRB_ERR_FIELD_TOOLONG = ErrorCode.new('KRB_ERR_FIELD_TOOLONG', 61, 'Field is too long for this implementation')
            KDC_ERR_CLIENT_NOT_TRUSTED = ErrorCode.new('KDC_ERR_CLIENT_NOT_TRUSTED', 62, 'PKINIT - KDC_ERR_CLIENT_NOT_TRUSTED')
            KDC_ERR_KDC_NOT_TRUSTED = ErrorCode.new('KDC_ERR_KDC_NOT_TRUSTED', 63, 'PKINIT - KDC_ERR_KDC_NOT_TRUSTED')
            KDC_ERR_INVALID_SIG = ErrorCode.new('KDC_ERR_INVALID_SIG', 64, 'PKINIT - KDC_ERR_INVALID_SIG')
            KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED = ErrorCode.new('KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED', 65, 'PKINIT - KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED')
            KDC_ERR_CERTIFICATE_MISMATCH = ErrorCode.new('KDC_ERR_CERTIFICATE_MISMATCH', 66, 'PKINIT - KDC_ERR_CERTIFICATE_MISMATCH')
            KRB_AP_ERR_NO_TGT = ErrorCode.new('KRB_AP_ERR_NO_TGT', 67, 'No TGT available to validate USER-TO-USER')
            KDC_ERR_WRONG_REALM = ErrorCode.new('KDC_ERR_WRONG_REALM', 68, 'Wrong Realm / domain')
            KRB_AP_ERR_USER_TO_USER_REQUIRED = ErrorCode.new('KRB_AP_ERR_USER_TO_USER_REQUIRED', 69, 'Ticket must be for USER-TO-USER')
            KDC_ERR_CANT_VERIFY_CERTIFICATE = ErrorCode.new('KDC_ERR_CANT_VERIFY_CERTIFICATE', 70, 'PKINIT - KDC_ERR_CANT_VERIFY_CERTIFICATE')
            KDC_ERR_INVALID_CERTIFICATE = ErrorCode.new('KDC_ERR_INVALID_CERTIFICATE', 71, 'PKINIT - KDC_ERR_INVALID_CERTIFICATE')
            KDC_ERR_REVOKED_CERTIFICATE = ErrorCode.new('KDC_ERR_REVOKED_CERTIFICATE', 72, 'PKINIT - KDC_ERR_REVOKED_CERTIFICATE')
            KDC_ERR_REVOCATION_STATUS_UNKNOWN = ErrorCode.new('KDC_ERR_REVOCATION_STATUS_UNKNOWN', 73, 'PKINIT - KDC_ERR_REVOCATION_STATUS_UNKNOWN')
            KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = ErrorCode.new('KDC_ERR_REVOCATION_STATUS_UNAVAILABLE', 74, 'PKINIT - KDC_ERR_REVOCATION_STATUS_UNAVAILABLE')
            KDC_ERR_CLIENT_NAME_MISMATCH = ErrorCode.new('KDC_ERR_CLIENT_NAME_MISMATCH', 75, 'PKINIT - KDC_ERR_CLIENT_NAME_MISMATCH')
            KDC_ERR_KDC_NAME_MISMATCH = ErrorCode.new('KDC_ERR_KDC_NAME_MISMATCH', 76, 'PKINIT - KDC_ERR_KDC_NAME_MISMATCH')
            KDC_ERR_INCONSISTENT_KEY_PURPOSE = ErrorCode.new('KDC_ERR_INCONSISTENT_KEY_PURPOSE', 77, 'PKINIT - KDC_ERR_INCONSISTENT_KEY_PURPOSE')
            KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = ErrorCode.new('KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED', 78, 'PKINIT - KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED')
            KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = ErrorCode.new('KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED', 79, 'PKINIT - KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED')
            KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = ErrorCode.new('KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED', 80, 'PKINIT - KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED')
            KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = ErrorCode.new('KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED', 81, 'PKINIT - KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED')

            # Allow lookup of errors via numerical value
            ERROR_MAP = ErrorCodes.constants.each_with_object({}) do |const, map|
              next if const == :ERROR_MAP

              error_code = ErrorCodes.const_get(const)
              map[error_code.value] = error_code
            end
          end

          # Runtime Error which can be raised by the Rex::Proto::Kerberos API
          class KerberosError < ::StandardError
            # @return [Rex::Proto::Kerberos::Model::Error::ErrorCode] A ErrorCode generated from a KDC
            attr_reader :error_code

            # @return [Rex::Proto::Kerberos::Model::KdcResponse, Rex::Proto::Kerberos::Model::EncKdcResponse] The response associated with this error
            attr_reader :res

            def initialize(message = nil, error_code: nil, res: nil)
              error_code ||= res&.error_code
              @error_code = error_code
              @res = res

              super(message || message_for(error_code))
            end

            def message_for(error_code)
              return "Kerberos Error" unless error_code

              if error_code == ErrorCodes::KRB_AP_ERR_SKEW && res&.respond_to?(:stime)
                now = Time.now
                skew = (res.stime - now).abs.to_i
                return "#{error_code}. Local time: #{now}, Server time: #{res.stime}, off by #{skew} seconds"
              elsif error_code == ErrorCodes::KDC_ERR_CLIENT_REVOKED && res&.respond_to?(:e_data) && res.e_data.present?
                begin
                  pa_datas = res.e_data_as_pa_data
                rescue OpenSSL::ASN1::ASN1Error
                else
                  pa_data_entry = pa_datas.find do |pa_data|
                    pa_data.type == Rex::Proto::Kerberos::Model::PreAuthType::KERB_SUPERSEDED_BY_USER
                  end

                  if pa_data_entry
                    error_code = "#{error_code}. This account has been superseded by #{pa_data_entry.decoded_value}."
                  end
                end
              end

              "Kerberos Error - #{error_code}"
            end
          end

          # Runtime Decoding Error which can be raised by the Rex::Proto::Kerberos API
          class KerberosDecodingError < KerberosError
            def initialize(message = nil)
              super(message || "Kerberos Decoding Error")
            end
          end

          # Runtime Error which can be raised by the Rex::Proto::Kerberos API when the Kerberos target does not support
          # the chosen Encryption method
          class KerberosEncryptionNotSupported < KerberosError
            # @return [Number] One of the encryption types defined within Rex::Proto::Kerberos::Crypto
            attr_reader :encryption_type

            def initialize(message = nil, encryption_type: nil)
              super(message || "Kerberos target does not support the required encryption")
            end
          end
        end
      end
    end
  end
end
