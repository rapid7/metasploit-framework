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
ARCH_IA32  = 'ia32'
ARCH_MIPS  = 'mips'
ARCH_PPC   = 'ppc'
ARCH_SPARC = 'sparc'

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

end
