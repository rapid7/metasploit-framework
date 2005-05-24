#!/usr/bin/ruby

#
# make sure the namespace is created
#

module Rex
module Encoding
module Xor
end end end

#
# include the Xor encodings
#

require 'Rex/Encoding/Xor/Generic'
require 'Rex/Encoding/Xor/Byte'
require 'Rex/Encoding/Xor/Word'
