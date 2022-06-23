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
            # @param [Object] other_object the object to test equality against
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

          # https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
          # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768#table-2-kerberos-ticket-flags
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
            KRB_ERR_GENERIC = ErrorCode.new('KRB_ERR_GENERIC', 60, 'Generic error')
            KRB_ERR_FIELD_TOOLONG = ErrorCode.new('KRB_ERR_FIELD_TOOLONG', 61, 'Field is too long for this implementation')
            KDC_ERR_WRONG_REALM = ErrorCode.new('KDC_ERR_WRONG_REALM', 68, 'Wrong Realm / domain')

            # Allow lookup of errors via numerical value
            ERROR_MAP = ErrorCodes.constants.each_with_object({}) do |const, map|
              next if const == :ERROR_MAP

              error_code = ErrorCodes.const_get(const)
              map[error_code.value] = error_code
            end
          end

          # Runtime Error which can be raised by the Rex::Proto::Kerberos API
          class KerberosError < ::StandardError
          end

          # Runtime Decoding Error which can be raised by the Rex::Proto::Kerberos API
          class KerberosDecodingError < KerberosError
          end
        end
      end
    end
  end
end
