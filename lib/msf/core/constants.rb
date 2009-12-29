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
MODULE_AUX     = 'auxiliary'
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
ManualRanking       = 0
LowRanking          = 100
AverageRanking      = 200
NormalRanking       = 300
GoodRanking         = 400
GreatRanking        = 500
ExcellentRanking    = 600
RankingName         =
	{
		ManualRanking    => "manual",	
		LowRanking       => "low",
		AverageRanking   => "average",
		NormalRanking    => "normal",
		GoodRanking      => "good",
		GreatRanking     => "great",
		ExcellentRanking => "excellent"
	}

module HttpClients
	IE = "MSIE"
	FF = "Firefox"
	SAFARI = "Safari"
	OPERA  = "Opera"

	UNKNOWN = "Unknown"
end
module OperatingSystems
	LINUX   = "Linux"
	MAC_OSX = "MacOSX"
	WINDOWS = "Windows"

	module WindowsVersions
		XP    = "XP"
		TWOK  = "2000"
		TWOK3 = "2003"
		VISTA = "Vista"
	end

	UNKNOWN = "Unknown"
end
end

#
# Global constants
#

# Licenses
MSF_LICENSE      = "Metasploit Framework License (BSD)"
GPL_LICENSE      = "GNU Public License v2.0"
BSD_LICENSE      = "BSD License"
ARTISTIC_LICENSE = "Perl Artistic License"
UNKNOWN_LICENSE  = "Unknown License"
LICENSES         =
	[
		MSF_LICENSE,
		GPL_LICENSE,
		BSD_LICENSE,
		ARTISTIC_LICENSE,
		UNKNOWN_LICENSE
	]
