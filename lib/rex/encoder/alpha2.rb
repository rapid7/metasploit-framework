#!/usr/bin/env ruby

#
# make sure the namespace is created
#

module Rex
module Encoder
module Alpha2
end end end

#
# include the Alpha2 encodings
#

require 'rex/encoder/alpha2/generic'
require 'rex/encoder/alpha2/alpha_mixed'
require 'rex/encoder/alpha2/alpha_upper'
require 'rex/encoder/alpha2/unicode_mixed'
require 'rex/encoder/alpha2/unicode_upper'
