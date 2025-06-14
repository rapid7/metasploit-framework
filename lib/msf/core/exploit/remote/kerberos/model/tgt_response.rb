# -*- coding: binary -*-

# A helper response object associated with a call to send_request_tgt.
class Msf::Exploit::Remote::Kerberos::Model::TgtResponse
  # @return [Rex::Proto::Kerberos::Model::EncKdcResponse] The Kerberos AS REP
  attr_reader :as_rep

  # @return [Hash{String => object},nil] The KrbEnctype used, including enctype, key, and a salt. Nil if pre-auth was not required
  # @see Rex::Proto::Kerberos::Crypto::Encryption
  attr_reader :krb_enc_key

  # @return [TrueClass, FalseClass] False if the ticket was created without requiring preauthentication, otherwise true.
  attr_reader :preauth_required

  # @return [Rex::Proto::Kerberos::Model::EncKdcResponse] The decrypted enc-part
  attr_reader :decrypted_part

  # @param [Rex::Proto::Kerberos::Model::EncKdcResponse] as_rep The Kerberos AS REP
  # @param [Hash{String => object}] The KrbEnctype used, including enctype, key, and a salt
  # @param [TrueClass, FalseClass] preauth_required False the ticket was created without requiring preauthentication, otherwise true.
  # @param [Rex::Proto::Kerberos::Model::EncKdcResponse] decrypted_part The decrypted response
  def initialize(as_rep:, krb_enc_key:, preauth_required:, decrypted_part:)
    raise ArgumentError.new("Missing required option :enctype") if krb_enc_key && krb_enc_key[:enctype].blank?
    raise ArgumentError.new("Missing required option :key") if krb_enc_key && krb_enc_key[:key].blank?

    @as_rep = as_rep
    @krb_enc_key = krb_enc_key
    @preauth_required = preauth_required
    @decrypted_part = decrypted_part
  end

  # @return [Rex::Proto::Kerberos::Model::Ticket] The Kerberos ticket
  def ticket
    @as_rep.ticket
  end
end
