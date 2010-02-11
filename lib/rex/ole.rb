##
# $Id$
# Version: $Revision$
##

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
#  6. support for auxillary streams (DocumentSummaryInformation and SummaryInformation)
#  7. support non-committal editing (open, change, close w/o save)
#  8. support timestamps
#  9. provide interface to change paramters (endian, etc)
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


end
end
