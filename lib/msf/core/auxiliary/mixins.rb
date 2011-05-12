##
# $Id$
##

#
# Auxiliary mixins
#
module Msf
class Auxiliary
	# Main types of auxiliary modules
	autoload :AuthBrute, 'msf/core/auxiliary/auth_brute'
	autoload :Dos,       'msf/core/auxiliary/dos'
	autoload :Fuzzer,    'msf/core/auxiliary/fuzzer'
	autoload :Scanner,   'msf/core/auxiliary/scanner'
	autoload :Timed,     'msf/core/auxiliary/timed'

	# WMAP
	autoload :WMAPModule,          'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanSSL,         'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanFile,        'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanDir,         'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanServer,      'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanQuery,       'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanUniqueQuery, 'msf/core/auxiliary/wmapmodule'
	autoload :WMAPScanGeneric,     'msf/core/auxiliary/wmapmodule'
	autoload :WMAPCrawler,         'msf/core/auxiliary/wmapmodule'
	autoload :HttpCrawler, 'msf/core/auxiliary/crawler'

	# Miscallaneous
	autoload :Report,       'msf/core/auxiliary/report'
	autoload :CommandShell, 'msf/core/auxiliary/commandshell'
	autoload :Nmap,         'msf/core/auxiliary/nmap'

	# Protocol augmenters for Aux modules
	autoload :Login,     'msf/core/auxiliary/login'
	autoload :RServices, 'msf/core/auxiliary/rservices'
	autoload :Cisco,     'msf/core/auxiliary/cisco'
end
end
