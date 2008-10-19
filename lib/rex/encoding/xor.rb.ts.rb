#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

#
# Xor Encoding Test Suite
#

require 'test/unit'
require 'rex/encoding/xor/generic.rb.ut'
require 'rex/encoding/xor/byte.rb.ut'
require 'rex/encoding/xor/word.rb.ut'
require 'rex/encoding/xor/dword.rb.ut'
require 'rex/encoding/xor/dword_additive.rb.ut'