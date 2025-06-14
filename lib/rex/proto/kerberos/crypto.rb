# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/proto/kerberos/crypto/rc4_hmac'
require 'rex/proto/kerberos/crypto/rsa_md5'

module Rex
  module Proto
    module Kerberos
      module Crypto
        # https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.1 - A unique number used as part of encryption to make certain types of
        # cryptographic attacks harder
        module KeyUsage
          AS_REQ_PA_ENC_TIMESTAMP                        = 1
          KDC_REP_TICKET                                 = 2
          AS_REP_ENCPART                                 = 3
          TGS_REQ_KDC_REQ_BODY_AUTHDATA_SESSION_KEY      = 4
          TGS_REQ_KDC_REQ_BODY_AUTHDATA_SUB_KEY          = 5
          TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM = 6
          TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR        = 7
          TGS_REP_ENCPART_SESSION_KEY                    = 8
          TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY          = 9
          AP_REQ_AUTHENTICATOR_CHKSUM                    = 10
          AP_REQ_AUTHENTICATOR                           = 11
          AP_REP_ENCPART                                 = 12
          KRB_PRIV_ENCPART                               = 13
          KRB_CRED_ENCPART                               = 14
          KRB_SAFE_CHKSUM                                = 15
          KERB_NON_KERB_SALT                             = 16
          KERB_NON_KERB_CKSUM_SALT                       = 17
          GSS_ACCEPTOR_SEAL                              = 22
          GSS_ACCEPTOR_SIGN                              = 23
          GSS_INITIATOR_SEAL                             = 24
          GSS_INITIATOR_SIGN                             = 25
        end

        module Checksum
          RSA_MD5 = 7
          MD5_DES = 8
          SHA1_DES3 = 12
          SHA1_AES128 = 15
          SHA1_AES256 = 16
          HMAC_MD5 = -138

          def self.from_checksum_type(ctype)
            checksummers = {
              RSA_MD5     => Rex::Proto::Kerberos::Crypto::RsaMd5,
              MD5_DES     => Rex::Proto::Kerberos::Crypto::DesCbcMd5,
              SHA1_DES3   => Rex::Proto::Kerberos::Crypto::Des3CbcSha1,
              SHA1_AES128 => Rex::Proto::Kerberos::Crypto::Aes128CtsSha1,
              SHA1_AES256 => Rex::Proto::Kerberos::Crypto::Aes256CtsSha1,
              HMAC_MD5    => Rex::Proto::Kerberos::Crypto::Rc4Hmac,
              0xffffff76  => Rex::Proto::Kerberos::Crypto::Rc4Hmac, # Negative 138 two's complement
            }
            result = checksummers[ctype]
            raise ::NotImplementedError, 'Checksum type is not supported' if result == nil

            result.new
          end

        end

        # https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml
        module Encryption
          DES_CBC_CRC = 1
          DES_CBC_MD4 = 2
          DES_CBC_MD5 = 3
          DES3_CBC_SHA1 = 16
          AES128 = 17
          AES256 = 18
          RC4_HMAC = 23

          # Mapping of encryption type numbers to the human readable text description by IANA
          # https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml
          IANA_NAMES = {
            DES_CBC_CRC => 'des-cbc-crc',
            DES_CBC_MD4 => 'des-cbc-md4',
            DES_CBC_MD5 => 'des-cbc-md5',
            DES3_CBC_SHA1 => 'des3-cbc-sha1-kd',
            AES128 => 'aes128-cts-hmac-sha1-96',
            AES256 => 'aes256-cts-hmac-sha1-96',
            RC4_HMAC => 'rc4-hmac'
          }

          # The default etypes to offer to the Kerberos server when none is provided
          DefaultOfferedEtypes = [AES256, AES128, RC4_HMAC, DES_CBC_MD5, DES3_CBC_SHA1]
          PkinitEtypes = [AES256, AES128]

          # The individual etype used by an encryptor when none is provided
          DefaultEncryptionType = RC4_HMAC

          ENCRYPTORS = {
            DES_CBC_MD5 =>   Rex::Proto::Kerberos::Crypto::DesCbcMd5,
            DES3_CBC_SHA1 => Rex::Proto::Kerberos::Crypto::Des3CbcSha1,
            RC4_HMAC =>      Rex::Proto::Kerberos::Crypto::Rc4Hmac,
            AES128 =>        Rex::Proto::Kerberos::Crypto::Aes128CtsSha1,
            AES256 =>        Rex::Proto::Kerberos::Crypto::Aes256CtsSha1,
          }
          private_constant :ENCRYPTORS

          SUPPORTED_ENCRYPTIONS = ENCRYPTORS.keys

          #
          # Return a string representation of the constant for a number
          #
          # @param [Integer] code
          def self.const_name(code)
            (self.constants - [:DefaultEncryptionType]).each do |c|
              return c.to_s if self.const_get(c) == code
            end
            return nil
          end

          # Return a integer value for the given encryption const name
          #
          # @param [String] const_name
          def self.value_for(const_name)
            self.const_get(const_name)
          end

          # @param [Integer] etype
          # @return [Rex::Proto::Kerberos::Crypto::BlockCipherBase]
          def self.from_etype(etype)
            result = ENCRYPTORS[etype]
            raise ::NotImplementedError, "EncryptedData schema #{etype.inspect} is not supported" if result == nil

            result.new
          end
        end
      end
    end
  end
end
