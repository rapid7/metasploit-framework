# BinData -- Binary data manipulator.
# Copyright (c) 2007,2008 Dion Mendel.

require 'bindata/array'
require 'bindata/bits'
require 'bindata/choice'
require 'bindata/float'
require 'bindata/int'
require 'bindata/multi_value'
require 'bindata/rest'
require 'bindata/single_value'
require 'bindata/string'
require 'bindata/stringz'
require 'bindata/struct'

# = BinData
# 
# A declarative way to read and write structured binary data.
# 
module BinData
  VERSION = "0.9.2-eofpatch" # Temporary fork for PacketFu.
end