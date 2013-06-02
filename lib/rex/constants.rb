# -*- coding: binary -*-
#
# Log severities
#
LOG_ERROR = 'error'
LOG_DEBUG = 'debug'
LOG_INFO  = 'info'
LOG_WARN  = 'warn'
LOG_RAW   = 'raw'

##
#
# Log levels
#
##

#
# LEV_0 - Default
#
# This log level is the default log level if none is specified.  It should be
# used when a log message should always be displayed when logging is enabled.
# Very few log messages should occur at this level aside from necessary
# information logging and error/warning logging.  Debug logging at level zero
# is not advised.
#
LEV_0     = 0

#
# LEV_1 - Extra
#
# This log level should be used when extra information may be needed to
# understand the cause of an error or warning message or to get debugging
# information that might give clues as to why something is happening.  This
# log level should be used only when information may be useful to understanding
# the behavior of something at a basic level.  This log level should not be
# used in an exhaustively verbose fashion.
#
LEV_1     = 1

#
# LEV_2 - Verbose
#
# This log level should be used when verbose information may be needed to
# analyze the behavior of the framework.  This should be the default log
# level for all detailed information not falling into LEV_0 or LEV_1.
# It is recommended that this log level be used by default if you are
# unsure.
#
LEV_2     = 2

#
# LEV_3 - Insanity
#
# This log level should contain very verbose information about the
# behavior of the framework, such as detailed information about variable
# states at certain phases including, but not limited to, loop iterations,
# function calls, and so on.  This log level will rarely be displayed,
# but when it is the information provided should make it easy to analyze
# any problem.
#
LEV_3     = 3


#
# Architecture constants
#
ARCH_ANY    = '_any_'
ARCH_X86    = 'x86'
ARCH_X86_64 = 'x86_64'
ARCH_X64    = 'x64' # To be used for compatability with ARCH_X86_64
ARCH_MIPS   = 'mips'
ARCH_MIPSLE = 'mipsle'
ARCH_MIPSBE = 'mipsbe'
ARCH_PPC    = 'ppc'
ARCH_PPC64  = 'ppc64'
ARCH_CBEA   = 'cbea'
ARCH_CBEA64 = 'cbea64'
ARCH_SPARC  = 'sparc'
ARCH_CMD    = 'cmd'
ARCH_PHP    = 'php'
ARCH_TTY    = 'tty'
ARCH_ARMLE  = 'armle'
ARCH_ARMBE  = 'armbe'
ARCH_JAVA   = 'java'
ARCH_RUBY   = 'ruby'
ARCH_DALVIK = 'dalvik'
ARCH_TYPES  =
	[
		ARCH_X86,
		ARCH_X86_64,
		ARCH_MIPS,
		ARCH_MIPSLE,
		ARCH_MIPSBE,
		ARCH_PPC,
		ARCH_PPC64,
		ARCH_CBEA,
		ARCH_CBEA64,
		ARCH_SPARC,
		ARCH_ARMLE,
		ARCH_ARMBE,
		ARCH_CMD,
		ARCH_PHP,
		ARCH_TTY,
		ARCH_JAVA,
		ARCH_RUBY,
		ARCH_DALVIK
	]

ARCH_ALL = ARCH_TYPES

#
# Endian constants
#
ENDIAN_LITTLE = 0
ENDIAN_BIG    = 1

IS_ENDIAN_LITTLE = ( [1].pack('s') == "\x01\x00" ) ? true : false
IS_ENDIAN_BIG    = ( not IS_ENDIAN_LITTLE )
