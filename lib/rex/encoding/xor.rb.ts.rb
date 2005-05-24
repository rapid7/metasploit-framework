#!/usr/bin/ruby

$:.unshift(File.join('..', '..', File.dirname(__FILE__)))

#
# Xor Encoding Test Suite
#

require 'test/unit'
require 'Rex/Encoding/Xor/Generic.rb.ut'
require 'Rex/Encoding/Xor/Byte.rb.ut'
require 'Rex/Encoding/Xor/Word.rb.ut'
require 'Rex/Encoding/Xor/DWord.rb.ut'
