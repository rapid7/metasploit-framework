module Dnsruby
  class RR
    # RFC4034, section 2
    # DNSSEC uses public key cryptography to sign and authenticate DNS
    # resource record sets (RRsets).  The public keys are stored in DNSKEY
    # resource records and are used in the DNSSEC authentication process
    # described in [RFC4035]: A zone signs its authoritative RRsets by
    # using a private key and stores the corresponding public key in a
    # DNSKEY RR.  A resolver can then use the public key to validate
    # signatures covering the RRsets in the zone, and thus to authenticate
    # them.
    class CDNSKEY < DNSKEY
      ClassValue = nil #:nodoc: all
      TypeValue = Types::CDNSKEY #:nodoc: all
    end
  end
end