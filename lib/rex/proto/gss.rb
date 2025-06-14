# -*- coding: binary -*-

module Rex::Proto::Gss
  OID_SPNEGO = OpenSSL::ASN1::ObjectId.new('1.3.6.1.5.5.2')
  OID_MICROSOFT_KERBEROS_5 = OpenSSL::ASN1::ObjectId.new('1.2.840.48018.1.2.2')
  OID_KERBEROS_5 = OpenSSL::ASN1::ObjectId.new('1.2.840.113554.1.2.2')
  KRB_AP_REQ_CHKSUM_TYPE = 0x8003

  module Mechanism
    KERBEROS = 'kerberos'
    SPNEGO = 'spnego'
  end
end
