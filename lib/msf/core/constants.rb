###
#
# This file contains constants that are referenced by the core 
# framework and by framework modules.
#
###

module Msf

#
# Architecture constants
#
ARCH_ANY   = '_any_'
ARCH_X86   = 'x86'
ARCH_MIPS  = 'mips'
ARCH_PPC   = 'ppc'
ARCH_SPARC = 'sparc'
ARCH_TYPES =
	[
		ARCH_X86,
		ARCH_MIPS,
		ARCH_PPC,
		ARCH_SPARC
	]

#
# Module types
#
MODULE_ANY     = '_any_'
MODULE_ENCODER = 'encoder'
MODULE_EXPLOIT = 'exploit'
MODULE_NOP     = 'nop'
MODULE_RECON   = 'recon'
MODULE_PAYLOAD = 'payload'
MODULE_TYPES   = 
	[ 
		MODULE_ENCODER, 
		MODULE_PAYLOAD, 
		MODULE_EXPLOIT, 
		MODULE_NOP, 
		MODULE_RECON 
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

end
