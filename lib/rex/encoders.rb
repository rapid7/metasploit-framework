##
# $Id$
#
# This file maps encoders for autoload
##
require 'rex'

module Rex::Encoders
	autoload :XorDword,         'rex/encoders/xor_dword'
	autoload :XorDwordAdditive, 'rex/encoders/xor_dword_additive'
end
