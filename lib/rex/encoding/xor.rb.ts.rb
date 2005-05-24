#!/usr/bin/ruby

$:.unshift(File.join('..', '..', File.dirname(__FILE__)))

#
# Xor Encoding Test Suite
#

require 'test/unit'
require 'Rex/Encoding/Xor/Generic.ut'
require 'Rex/Encoding/Xor/Byte.ut'
require 'Rex/Encoding/Xor/Word.ut'
require 'Rex/Encoding/Xor/DWord.ut'
