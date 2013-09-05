# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
#
# License: MSF_LICENSE
#
#
# This module implements Object-Linking-and-Embedding otherwise known as
# Compound File Binary File Format or Windows Compound Binary File Format.
# OLE is the container format for modern Excel, Word, PowerPoint, and many
# other file formats.
#
# NOTE: This implementation is almost fully compliant with [MS-CFB] v1.1
#
#
# SUPPORTS:
#
#  1. R/W v3 OLE files (v4 may work, but wasn't tested)
#  2. RO double-indirect fat sectors
#  3. RO fat sectors (including those in double-indirect parts)
#  4. WO support for less than 109 fat sectors :)
#  5. R/W minifat sectors
#  6. R/W ministream
#  7. R/W normal streams
#  8. R/W substorages (including nesting)
#  9. full directory support (hierarchal and flattened access)
# 10. big and little endian files (although only little endian was tested)
# 11. PropertySet streams (except .to_s)
#
#
# TODO (in order of priority):
#
#  1. support deleting storages/streams
#  2. create copyto and other typical interface functions
#  3. support writing DIF sectors > 109
#     - may lead to allocating more fat sectors :-/
#  4. properly support mode params for open_stream/open_storage/etc
#  5. optimize to prevent unecessary loading/writing
#  6. support non-committal editing (open, change, close w/o save)
#  7. support timestamps
#  8. provide interface to change paramters (endian, etc)
#
#
# TO INVESTIGATE:
#
#  1. moving storage interface functions into something used by both
#     the main storage and substorages (unifying the code) (mixin?)
#  2. eliminating flattening the directory prior to writing it out
#
##

require 'rex'

module Rex
module OLE

# misc util
# NOTE: the v1.1 spec says that everything "MUST be stored in little-endian byte order"
BIG_ENDIAN     = 0xfeff
LITTLE_ENDIAN  = 0xfffe
# defines Util class
require 'rex/ole/util'
require 'rex/ole/clsid'


# constants for dealing with the header
HDR_SZ  = 512
# signatures
SIG       = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
SIG_BETA  = "\x0e\x11\xfc\x0d\xd0\xcf\x11\xe0"
# defines Header class
require 'rex/ole/header'


# sector types
SECT_MAX   = 0xfffffffa
SECT_DIF   = 0xfffffffc
SECT_FAT   = 0xfffffffd
SECT_END   = 0xfffffffe
SECT_FREE  = 0xffffffff
# defines DIFAT class
require 'rex/ole/difat'
# defines FAT class
require 'rex/ole/fat'
# defines MiniFAT class
require 'rex/ole/minifat'


# directory entries
DIRENTRY_SZ      = 128
DIR_NOSTREAM     = 0xffffffff
DIR_MAXREGSID    = 0xfffffffa
# defines Directory class
require 'rex/ole/directory'

# types
STGTY_INVALID    = 0
STGTY_STORAGE    = 1
STGTY_STREAM     = 2
STGTY_LOCKBYTES  = 3
STGTY_PROPERTY   = 4
STGTY_ROOT       = 5
# for red/black tree
COLOR_RED   = 0
COLOR_BLACK = 1
# defines DirEntry base class
require 'rex/ole/direntry'


# constants for storages
STGM_READ       = 0
STGM_WRITE      = 1
STGM_READWRITE  = 2
# defines Storage class
require 'rex/ole/storage'
# defines SubStorage class
require 'rex/ole/substorage'
# defines Stream class
require 'rex/ole/stream'


# constants for property sets
# PropertyIds
PID_DICTIONARY  = 0x00000000
PID_CODEPAGE    = 0x00000001
PID_LOCALE      = 0x80000000
PID_BEHAVIOR    = 0x80000003
# Well-known PropertyIds
PIDSI_TITLE        = 0x02
PIDSI_SUBJECT      = 0x03
PIDSI_AUTHOR       = 0x04
PIDSI_KEYWORDS     = 0x05
PIDSI_COMMENTS     = 0x06
PIDSI_TEMPLATE     = 0x07
PIDSI_LASTAUTHOR   = 0x08
PIDSI_REVNUMBER    = 0x09
PIDSI_EDITTIME     = 0x0a
PIDSI_LASTPRINTED  = 0x0b
PIDSI_CREATE_DTM   = 0x0c
PIDSI_LASTSAVE_DTM = 0x0d
PIDSI_PAGECOUNT    = 0x0e
PIDSI_WORDCOUNT    = 0x0f
PIDSI_CHARCOUNT    = 0x10
PIDSI_THUMBNAIL    = 0x11
PIDSI_APPNAME      = 0x12
PIDSI_DOC_SECURITY = 0x13
# PropertyTypes
VT_EMPTY        = 0x00
VT_NULL         = 0x01
VT_I2           = 0x02
VT_I4           = 0x03
VT_R4           = 0x04
VT_R8           = 0x05
VT_CY           = 0x06
VT_DATE         = 0x07
VT_BSTR         = 0x08
VT_ERROR        = 0x0a
VT_BOOL         = 0x0b
VT_VARIANT      = 0x0c # used with VT_VECTOR
# 0xd
VT_DECIMAL      = 0x0e
# 0xf
VT_I1           = 0x10
VT_UI1          = 0x11
VT_UI2          = 0x12
VT_UI4          = 0x13
VT_I8           = 0x14
VT_UI8          = 0x15
VT_INT          = 0x16
VT_UINT         = 0x17
VT_LPSTR        = 0x1e
VT_LPWSTR       = 0x1f
# 0x20-0x3f
VT_FILETIME     = 0x40
VT_BLOB         = 0x41
VT_STREAM       = 0x42
VT_STORAGE      = 0x43
VT_STREAMED_OBJ = 0x44
VT_STORED_OBJ   = 0x45
VT_BLOB_OBJ     = 0x46
VT_CF           = 0x47 # Clipboard Format
VT_CLSID        = 0x48
VT_VERSIONED_STREAM = 0x49
# Flags
VT_VECTOR       = 0x1000
VT_ARRAY        = 0x2000 # Requires OLE version >= 1
# Format IDs
FMTID_SummaryInformation    = "\xe0\x85\x9f\xf2\xf9\x4f\x68\x10\xab\x91\x08\x00\x2b\x27\xb3\xd9"
FMTID_DocSummaryInformation = "\x02\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae"
FMTID_UserDefinedProperties = "\x05\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae"
FMTID_GlobalInfo            = "\x00\x6f\x61\x56\x54\xc1\xce\x11\x85\x53\x00\xaa\x00\xa1\xf9\x5b"
FMTID_ImageContents         = "\x00\x64\x61\x56\x54\xc1\xce\x11\x85\x53\x00\xaa\x00\xa1\xf9\x5b"
FMTID_ImageInfo             = "\x00\x65\x61\x56\x54\xc1\xce\x11\x85\x53\x00\xaa\x00\xa1\xf9\x5b"
FMTID_PropertyBag           = "\x01\x18\x00\x20\xe6\x5d\xd1\x11\x8e\x38\x00\xc0\x4f\xb9\x38\x6d"
# defines PropertySet class
require 'rex/ole/propset'


end
end
