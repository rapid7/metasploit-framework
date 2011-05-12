###
#
# framework-util
# --------------
#
# The util library miscellaneous routines that involve the framework
# API, but are not directly related to the core/base/ui structure.
#
###


require 'msf/core'

module Msf
module Util

	# Executable generation and encoding
	autoload :EXE, 'msf/util/exe'

	# Parse SVN entries
	autoload :SVN, 'msf/util/svn'

end
end
