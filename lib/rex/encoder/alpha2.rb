#!/usr/bin/env ruby

#
# ________________________________________________________________________________
# 
#     ,sSSs,,s,  ,sSSSs,  ALPHA 2: Zero-tolerance. (build 07)
#    SS"  Y$P"  SY"  ,SY
#   iS'   dY       ,sS"   Unicode-proof uppercase alphanumeric shellcode encoding.
#   YS,  dSb    ,sY"      Copyright (C) 2003, 2004 by Berend-Jan Wever.
#   `"YSS'"S' 'SSSSSSSP   <skylined@edup.tudelft.nl>
# ________________________________________________________________________________
#

#
# make sure the namespace is created
#

module Rex
module Encoder
module Alpha2

	#
	# autoload the Alpha2 encoders
	#
	autoload :Generic,      'rex/encoder/alpha2/generic'
	autoload :AlphaMixed,   'rex/encoder/alpha2/alpha_mixed'
	autoload :AlphaUpper,   'rex/encoder/alpha2/alpha_upper'
	autoload :UnicodeMixed, 'rex/encoder/alpha2/unicode_mixed'
	autoload :UnicodeUpper, 'rex/encoder/alpha2/unicode_upper'

end
end
end
