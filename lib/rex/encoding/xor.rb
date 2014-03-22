# -*- coding: binary -*-

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

require 'rex/encoding/xor/generic'
require 'rex/encoding/xor/byte'
require 'rex/encoding/xor/word'
require 'rex/encoding/xor/dword'
require 'rex/encoding/xor/qword'
