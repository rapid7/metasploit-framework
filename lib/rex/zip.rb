# -*- coding: binary -*-
#
# Zip library
#
# Written by Joshua J. Drake <jduck [at] metasploit.com>
#
# Based on code contributed by bannedit, and the following SPEC:
# Reference: http://www.pkware.com/documents/casestudies/APPNOTE.TXT
#

require 'zlib'

module Rex
module Zip

ZIP_VERSION = 0x14

# general purpose bit flag values
#
# bit 0
GPBF_ENCRYPTED      = 0x0001
# bits 1 & 2
# implode only
GPBF_IMP_8KDICT     = 0x0002
GPBF_IMP_3SFT       = 0x0004
# deflate only
GPBF_DEF_MAX        = 0x0002
GPBF_DEF_FAST       = 0x0004
GPBF_DEF_SUPERFAST  = 0x0006
# lzma only
GPBF_LZMA_EOSUSED   = 0x0002
# bit 3
GPBF_USE_DATADESC   = 0x0008
# bit 4
GPBF_DEF_ENHANCED   = 0x0010
# bit 5
GPBF_COMP_PATHCED   = 0x0020
# bit 6
GPBF_STRONG_ENC     = 0x0040
# bit 7-10 unused
# bit 11
GPBF_STRS_UTF8      = 0x0800
# bit 12 (reserved)
# bit 13
GPBF_DIR_ENCRYPTED  = 0x2000
# bit 14,15 (reserved)


# compression methods
CM_STORE            = 0
CM_SHRINK           = 1
CM_REDUCE1          = 2
CM_REDUCE2          = 3
CM_REDUCE3          = 4
CM_REDUCE4          = 5
CM_IMPLODE          = 6
CM_TOKENIZE         = 7
CM_DEFLATE          = 8
CM_DEFLATE64        = 9
CM_PKWARE_IMPLODE   = 10
# 11 - reserved
CM_BZIP2            = 12
# 13 - reserved
CM_LZMA_EFS         = 14
# 15-17 reserved
CM_IBM_TERSE        = 18
CM_IBM_LZ77         = 19
# 20-96 reserved
CM_WAVPACK          = 97
CM_PPMD_V1R1        = 98


# internal file attributes
IFA_ASCII           = 0x0001
# bits 2 & 3 are reserved
IFA_MAINFRAME_MODE  = 0x0002 # ??


# external file attributes
EFA_ISDIR           = 0x0001


# various parts of the structure
require 'rex/zip/blocks'

# an entry in a zip file
require 'rex/zip/entry'

# the archive class
require 'rex/zip/archive'

# a child of Archive, implements Java ARchives for creating java applications
require 'rex/zip/jar'

end
end
