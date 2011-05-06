##
# $Id$
#
# Map log sinks for autload
##

module Rex
module Logging
module Sinks

	autoload :Flatfile, 'rex/logging/sinks/flatfile'
	autoload :Stderr,   'rex/logging/sinks/stderr'

end
end
end
