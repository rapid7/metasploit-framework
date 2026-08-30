# -*- coding: binary -*-
module Rex
module Proto
module NTLM
class Constants

  SSP_SIGN = "NTLMSSP\0"
  BLOB_SIGN = 0x00000101
  LM_MAGIC = "KGS!@\#$%"
  TIME_OFFSET = 11644473600
  MAX64 = 0xffffffffffffffff

  FLAGS = {
  :UNICODE              => 0x00000001,
  :OEM                  => 0x00000002,
  :REQUEST_TARGET       => 0x00000004,
  #:UNKNOWN              => 0x00000008,
  :SIGN                 => 0x00000010,
  :SEAL                 => 0x00000020,
  #:UNKNOWN              => 0x00000040,
  :NETWARE              => 0x00000100,
  :NTLM                 => 0x00000200,
  #:UNKNOWN              => 0x00000400,
  #:UNKNOWN              => 0x00000800,
  :DOMAIN_SUPPLIED      => 0x00001000,
  :WORKSTATION_SUPPLIED => 0x00002000,
  :LOCAL_CALL           => 0x00004000,
  :ALWAYS_SIGN          => 0x00008000,
  :TARGET_TYPE_DOMAIN   => 0x00010000,
  :TARGET_INFO          => 0x00800000,
  :NTLM2_KEY            => 0x00080000,
  :KEY128               => 0x20000000,
  :KEY56                => 0x80000000
  }

  FLAG_KEYS = FLAGS.keys.sort{|a, b| FLAGS[a] <=> FLAGS[b] }

  DEFAULT_FLAGS = {
  :TYPE1 => FLAGS[:UNICODE] | FLAGS[:OEM] | FLAGS[:REQUEST_TARGET] | FLAGS[:NTLM] | FLAGS[:ALWAYS_SIGN] | FLAGS[:NTLM2_KEY],
  :TYPE2 => FLAGS[:UNICODE],
  :TYPE3 => FLAGS[:UNICODE] | FLAGS[:REQUEST_TARGET] | FLAGS[:NTLM] | FLAGS[:ALWAYS_SIGN] | FLAGS[:NTLM2_KEY]
  }

  # NTLM Response Type
  NTLM_V1_RESPONSE =		1
  NTLM_V2_RESPONSE =		2
  NTLM_2_SESSION_RESPONSE = 	3

  #the same flags but merged from lib/rex/proto/smb/constants and keeped for compatibility
  # NTLMSSP Message Flags
  NEGOTIATE_UNICODE     = 0x00000001  # Only set if Type 1 contains it - this or oem, not both
  NEGOTIATE_OEM         = 0x00000002  # Only set if Type 1 contains it - this or unicode, not both
  REQUEST_TARGET        = 0x00000004  # If set in Type 1, must return domain or server
  NEGOTIATE_SIGN        = 0x00000010  # Session signature required
  NEGOTIATE_SEAL        = 0x00000020  # Session seal required
  NEGOTIATE_LMKEY       = 0x00000080  # LM Session Key should be used for signing and sealing
  NEGOTIATE_NTLM        = 0x00000200  # NTLM auth is supported
  NEGOTIATE_ANONYMOUS   = 0x00000800  # Anonymous context used
  NEGOTIATE_DOMAIN      = 0x00001000  # Sent in Type1, client gives domain info
  NEGOTIATE_WORKSTATION = 0x00002000  # Sent in Type1, client gives workstation info
  NEGOTIATE_LOCAL_CALL  = 0x00004000  # Server and client are on same machine
  NEGOTIATE_ALWAYS_SIGN = 0x00008000  # Add signatures to packets
  TARGET_TYPE_DOMAIN    = 0x00010000  # If REQUEST_TARGET, we're adding the domain name
  TARGET_TYPE_SERVER    = 0x00020000  # If REQUEST_TARGET, we're adding the server name
  TARGET_TYPE_SHARE     = 0x00040000  # Supposed to denote "a share" but for a webserver?
  NEGOTIATE_NTLM2_KEY   = 0x00080000  # NTLMv2 Signature and Key exchanges
  NEGOTIATE_TARGET_INFO = 0x00800000  # Server set when sending Target Information Block
  NEGOTIATE_128         = 0x20000000  # 128-bit encryption supported
  NEGOTIATE_KEY_EXCH    = 0x40000000  # Client will supply encrypted master key in Session Key field of Type3 msg
  NEGOTIATE_56          = 0x80000000  # 56-bit encryption supported

end
end
end
end
