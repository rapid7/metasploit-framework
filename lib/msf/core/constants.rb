###
#
# This file contains constants that are referenced by the core 
# framework and by framework modules.
#
###

module Msf

#
# Module types
#
MODULE_ANY     = '_any_'
MODULE_ENCODER = 'encoder'
MODULE_EXPLOIT = 'exploit'
MODULE_NOP     = 'nop'
MODULE_AUX     = 'aux'
MODULE_PAYLOAD = 'payload'
MODULE_TYPES   = 
	[ 
		MODULE_ENCODER, 
		MODULE_PAYLOAD, 
		MODULE_EXPLOIT, 
		MODULE_NOP, 
		MODULE_AUX 
	]

#
# Module rankings
#
LowRanking       = 100
AverageRanking   = 200
NormalRanking    = 300
GoodRanking      = 400
GreatRanking     = 500
ExcellentRanking = 600
RankingName      =
	{
		LowRanking       => "low",
		AverageRanking   => "average",
		NormalRanking    => "normal",
		GoodRanking      => "good",
		GreatRanking     => "great",
		ExcellentRanking => "excellent"
	}

end

#
# Global constants
#

# Licenses
MSF_LICENSE      = "Metasploit Framework License v1.0"
GPL_LICENSE      = "GNU Public License v2.0"
ARTISTIC_LICENSE = "Perl Artistic License"
UNKNOWN_LICENSE  = "Unknown License"
