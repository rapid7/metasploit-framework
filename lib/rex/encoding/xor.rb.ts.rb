#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

#
# Xor Encoding Test Suite
#

require 'test/unit'
require 'rex/encoding/xor/generic.rb.ut'
require 'rex/encoding/xor/byte.rb.ut'
require 'rex/encoding/xor/word.rb.ut'
require 'rex/encoding/xor/d_word.rb.ut'
require 'rex/encoding/xor/d_word_additive.rb.ut'
